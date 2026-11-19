/* SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd. */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "ipwatchd.h"

#include <grp.h>
#include <json-c/json.h>

#define IPWD_SECURITY_LOADER_GROUP "deepin-daemon"
#define IPWD_ALLOWED_USER "lightdm"
#ifdef IPWD_SECURITY_LOADER_TEST
#define IPWD_SECURITY_LOADER_STATE_DIR "state"
#define IPWD_SECURITY_LOADER_STATE_FILE IPWD_SECURITY_LOADER_STATE_DIR "/allow-callers"
#define IPWD_SECURITY_LOADER_STATE_OWNER geteuid()
#else
#define IPWD_SECURITY_LOADER_STATE_DIR "/run/ipwatchd"
#define IPWD_SECURITY_LOADER_STATE_FILE IPWD_SECURITY_LOADER_STATE_DIR "/allow-callers"
#define IPWD_SECURITY_LOADER_STATE_OWNER ((uid_t)0)
#endif
#define IPWD_SECURITY_LOADER_SCOPE IPWD_DBUS_SERVICE ":" IPWD_DBUS_PATH
#define IPWD_SECURITY_LOADER_MAX_STATE_SIZE (1024 * 1024)

typedef struct IPWD_S_ALLOWED_CALLER {
  char *name;
  struct IPWD_S_ALLOWED_CALLER *next;
} IPWD_S_ALLOWED_CALLER;

static IPWD_S_ALLOWED_CALLER *allowed_callers;
static gid_t loader_group = (gid_t)-1;
static uid_t allowed_user = (uid_t)-1;
static char *system_bus_id;

static int remove_caller(const char *name) {
  IPWD_S_ALLOWED_CALLER **current = &allowed_callers;
  while (*current != NULL) {
    if (strcmp((*current)->name, name) == 0) {
      IPWD_S_ALLOWED_CALLER *removed = *current;
      *current = removed->next;
      free(removed->name);
      free(removed);
      return 1;
    }
    current = &(*current)->next;
  }
  return 0;
}

static int caller_allowed(const char *name) {
  IPWD_S_ALLOWED_CALLER *current;
  for (current = allowed_callers; current != NULL; current = current->next) {
    if (strcmp(current->name, name) == 0) return 1;
  }
  return 0;
}

static int add_caller(const char *name) {
  IPWD_S_ALLOWED_CALLER *entry;
  if (caller_allowed(name)) return 1;
  entry = calloc(1, sizeof(*entry));
  if (entry == NULL || (entry->name = strdup(name)) == NULL) {
    free(entry);
    return 0;
  }
  entry->next = allowed_callers;
  allowed_callers = entry;
  return 1;
}

static int compare_caller_names(const void *left, const void *right) {
  const char *const *left_name = left;
  const char *const *right_name = right;
  return strcmp(*left_name, *right_name);
}

static char **sorted_caller_names(size_t *count) {
  IPWD_S_ALLOWED_CALLER *current;
  char **names;
  size_t index = 0;

  *count = 0;
  for (current = allowed_callers; current != NULL; current = current->next) (*count)++;
  if (*count == 0) return NULL;
  names = calloc(*count, sizeof(*names));
  if (names == NULL) return NULL;
  for (current = allowed_callers; current != NULL; current = current->next) names[index++] = current->name;
  qsort(names, *count, sizeof(*names), compare_caller_names);
  return names;
}

static int process_in_group(unsigned long pid, gid_t group) {
  char path[64], line[1024];
  FILE *status;
  snprintf(path, sizeof(path), "/proc/%lu/status", pid);
  status = fopen(path, "r");
  if (status == NULL) return 0;
  while (fgets(line, sizeof(line), status) != NULL) {
    char *value;
    if (strncmp(line, "Groups:", 7) == 0) {
      value = line + 7;
    } else if (strncmp(line, "Gid:", 4) == 0) {
      value = line + 4;
    } else {
      continue;
    }
    while (*value != '\0') {
      char *end;
      unsigned long gid;
      while (*value == ' ' || *value == '\t') value++;
      if (*value == '\n' || *value == '\0') break;
      errno = 0;
      gid = strtoul(value, &end, 10);
      if (errno != 0 || end == value) break;
      if ((gid_t)gid == group) {
        fclose(status);
        return 1;
      }
      value = end;
    }
  }
  fclose(status);
  return 0;
}

static int is_descendant(unsigned long pid, unsigned long ancestor) {
  unsigned int depth;
  for (depth = 0; pid > 1 && depth < 128; depth++) {
    char path[64], line[256];
    FILE *status;
    unsigned long parent = 0;
    snprintf(path, sizeof(path), "/proc/%lu/status", pid);
    status = fopen(path, "r");
    if (status == NULL) return 0;
    while (fgets(line, sizeof(line), status) != NULL) {
      if (sscanf(line, "PPid:\t%lu", &parent) == 1) break;
    }
    fclose(status);
    if (parent == ancestor) return 1;
    if (parent == 0 || parent == pid) return 0;
    pid = parent;
  }
  return 0;
}

static int get_uid_and_pid(DBusConnection *conn, const char *name, unsigned long *uid, unsigned long *pid) {
  DBusError error;
  DBusMessage *request = NULL;
  DBusMessage *reply = NULL;
  dbus_uint32_t dbus_pid;
  dbus_error_init(&error);
  *uid = dbus_bus_get_unix_user(conn, name, &error);
  if (dbus_error_is_set(&error)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to get UID for %s: %s", name, error.message);
    dbus_error_free(&error);
    return 0;
  }
  request = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      DBUS_INTERFACE_DBUS, "GetConnectionUnixProcessID");
  if (request == NULL || !dbus_message_append_args(request, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID)) {
    if (request != NULL) dbus_message_unref(request);
    return 0;
  }
  reply = dbus_connection_send_with_reply_and_block(conn, request, -1, &error);
  dbus_message_unref(request);
  if (reply == NULL || !dbus_message_get_args(reply, &error, DBUS_TYPE_UINT32, &dbus_pid, DBUS_TYPE_INVALID)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to get PID for %s: %s", name,
        dbus_error_is_set(&error) ? error.message : "unknown error");
    if (reply != NULL) dbus_message_unref(reply);
    if (dbus_error_is_set(&error)) dbus_error_free(&error);
    return 0;
  }
  dbus_message_unref(reply);
  *pid = dbus_pid;
  if (dbus_error_is_set(&error)) {
    dbus_error_free(&error);
    return 0;
  }
  return 1;
}

static int load_system_bus_id(DBusConnection *conn) {
  DBusError error;
  DBusMessage *request = NULL;
  DBusMessage *reply = NULL;
  const char *id = NULL;
  char *copy = NULL;

  dbus_error_init(&error);
  request = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      DBUS_INTERFACE_DBUS, "GetId");
  if (request == NULL) goto out;
  reply = dbus_connection_send_with_reply_and_block(conn, request, -1, &error);
  if (reply == NULL || !dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID) ||
      id == NULL || id[0] == '\0' || (copy = strdup(id)) == NULL) {
    goto out;
  }
  free(system_bus_id);
  system_bus_id = copy;
  copy = NULL;

out:
  free(copy);
  if (reply != NULL) dbus_message_unref(reply);
  if (request != NULL) dbus_message_unref(request);
  if (dbus_error_is_set(&error)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to get system bus ID: %s", error.message);
    dbus_error_free(&error);
  }
  if (system_bus_id == NULL) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to get system bus ID");
    return 0;
  }
  return 1;
}

static int ensure_state_directory(void) {
  struct stat status;
  int dirfd;
  int valid = 0;

  if (mkdir(IPWD_SECURITY_LOADER_STATE_DIR, 0700) != 0 && errno != EEXIST) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to create security-loader state directory: %s", strerror(errno));
    return 0;
  }
  dirfd = open(IPWD_SECURITY_LOADER_STATE_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (dirfd < 0) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to open security-loader state directory: %s", strerror(errno));
    return 0;
  }
  if (fstat(dirfd, &status) != 0) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to inspect security-loader state directory: %s", strerror(errno));
    goto out;
  }
  if (!S_ISDIR(status.st_mode) || status.st_uid != IPWD_SECURITY_LOADER_STATE_OWNER) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Security-loader state directory has unsafe ownership");
    goto out;
  }
  if (fchmod(dirfd, 0700) != 0) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to secure security-loader state directory: %s", strerror(errno));
    goto out;
  }
  if (fstat(dirfd, &status) != 0) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to verify security-loader state directory: %s", strerror(errno));
    goto out;
  }
  if ((status.st_mode & 0777) != 0700) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Security-loader state directory permissions are not 0700");
    goto out;
  }
  valid = 1;

out:
  close(dirfd);
  return valid;
}

static int save_allow_callers(void) {
  char temporary[sizeof(IPWD_SECURITY_LOADER_STATE_FILE) + 16] = {0};
  char **names = NULL;
  const char *content;
  struct json_object *state = NULL, *scopes = NULL, *callers = NULL, *value = NULL;
  FILE *file = NULL;
  int fd = -1, dirfd = -1;
  int saved = 0;
  int saved_errno = 0;
  size_t count = 0, index;

  if (system_bus_id == NULL || !ensure_state_directory()) return 0;

  names = sorted_caller_names(&count);
  if (count != 0 && names == NULL) {
    errno = ENOMEM;
    goto out;
  }
  state = json_object_new_object();
  scopes = json_object_new_object();
  callers = json_object_new_array();
  value = json_object_new_string(system_bus_id);
  if (state == NULL || scopes == NULL || callers == NULL || value == NULL) {
    errno = ENOMEM;
    goto out;
  }
  json_object_object_add(state, "busId", value);
  value = NULL;
  for (index = 0; index < count; index++) {
    value = json_object_new_string(names[index]);
    if (value == NULL || json_object_array_add(callers, value) != 0) {
      if (value != NULL) json_object_put(value);
      value = NULL;
      errno = ENOMEM;
      goto out;
    }
    value = NULL;
  }
  json_object_object_add(scopes, IPWD_SECURITY_LOADER_SCOPE, callers);
  callers = NULL;
  json_object_object_add(state, "callers", scopes);
  scopes = NULL;
  content = json_object_to_json_string_ext(state, JSON_C_TO_STRING_PLAIN);
  if (content == NULL) {
    errno = ENOMEM;
    goto out;
  }

  snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", IPWD_SECURITY_LOADER_STATE_FILE);
  fd = mkstemp(temporary);
  if (fd < 0 || fchmod(fd, 0600) != 0 || (file = fdopen(fd, "w")) == NULL) goto out;
  fd = -1;
  if (fprintf(file, "%s\n", content) < 0) goto out;
  if (fflush(file) != 0 || fsync(fileno(file)) != 0) goto out;
  if (fclose(file) != 0) {
    file = NULL;
    goto out;
  }
  file = NULL;
  if (rename(temporary, IPWD_SECURITY_LOADER_STATE_FILE) != 0) goto out;
  saved = 1;
  dirfd = open(IPWD_SECURITY_LOADER_STATE_DIR, O_RDONLY | O_DIRECTORY);
  if (dirfd < 0 || fsync(dirfd) != 0) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to sync security-loader state directory: %s", strerror(errno));
  }

out:
  saved_errno = errno;
  if (file != NULL) fclose(file);
  if (fd >= 0) close(fd);
  if (!saved) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to save security-loader state: %s", strerror(saved_errno));
    if (temporary[0] != '\0') unlink(temporary);
  }
  if (dirfd >= 0) close(dirfd);
  if (value != NULL) json_object_put(value);
  if (callers != NULL) json_object_put(callers);
  if (scopes != NULL) json_object_put(scopes);
  if (state != NULL) json_object_put(state);
  free(names);
  return saved;
}

static int load_allow_callers(DBusConnection *conn) {
  struct stat status;
  struct json_object *state = NULL, *bus_id = NULL, *scopes = NULL, *callers = NULL;
  char *content = NULL;
  unsigned long uid, pid;
  size_t offset = 0;
  ssize_t length;
  int result = 1;
  int fd;
  size_t index, count;

  fd = open(IPWD_SECURITY_LOADER_STATE_FILE, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) {
    if (errno == ENOENT) return 1;
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to read security-loader state: %s", strerror(errno));
    return 0;
  }
  if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_uid != IPWD_SECURITY_LOADER_STATE_OWNER ||
      (status.st_mode & 0077) != 0 || status.st_size < 0 ||
      status.st_size > IPWD_SECURITY_LOADER_MAX_STATE_SIZE) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Security-loader state file has unsafe ownership, permissions, or size");
    result = 0;
    goto out;
  }
  content = calloc((size_t)status.st_size + 1, 1);
  if (content == NULL) {
    result = 0;
    goto out;
  }
  while (offset < (size_t)status.st_size) {
    length = read(fd, content + offset, (size_t)status.st_size - offset);
    if (length < 0) {
      if (errno == EINTR) continue;
      result = 0;
      goto out;
    }
    if (length == 0) break;
    offset += (size_t)length;
  }
  content[offset] = '\0';
  state = json_tokener_parse(content);
  if (state == NULL || !json_object_is_type(state, json_type_object) ||
      !json_object_object_get_ex(state, "busId", &bus_id) ||
      !json_object_is_type(bus_id, json_type_string) ||
      !json_object_object_get_ex(state, "callers", &scopes) ||
      !json_object_is_type(scopes, json_type_object)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Ignoring invalid security-loader state");
    goto out;
  }
  if (strcmp(json_object_get_string(bus_id), system_bus_id) != 0) {
    ipwd_message(IPWD_MSG_TYPE_INFO, "Ignoring security-loader state from a different system bus");
    goto out;
  }
  if (!json_object_object_get_ex(scopes, IPWD_SECURITY_LOADER_SCOPE, &callers)) goto out;
  if (!json_object_is_type(callers, json_type_array)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Ignoring invalid security-loader caller list");
    goto out;
  }
  count = json_object_array_length(callers);
  for (index = 0; index < count; index++) {
    struct json_object *caller = json_object_array_get_idx(callers, index);
    const char *name;
    if (caller == NULL || !json_object_is_type(caller, json_type_string)) continue;
    name = json_object_get_string(caller);
    if (name == NULL || name[0] != ':' || name[1] == '\0') continue;
    if (!get_uid_and_pid(conn, name, &uid, &pid)) continue;
    if (!add_caller(name)) {
      ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to restore security-loader caller");
      result = 0;
      goto out;
    }
    ipwd_message(IPWD_MSG_TYPE_INFO, "Restored security-loader caller %s", name);
  }

out:
  if (state != NULL) json_object_put(state);
  free(content);
  close(fd);
  return result;
}

int ipwd_securityloader_init(DBusConnection *conn) {
  DBusError error;
  struct group *group = getgrnam(IPWD_SECURITY_LOADER_GROUP);
  if (group != NULL) loader_group = group->gr_gid;
  struct passwd *pwd = getpwnam(IPWD_ALLOWED_USER);
  if (pwd != NULL) allowed_user = pwd->pw_uid;
  dbus_error_init(&error);
  dbus_bus_add_match(conn,
      "type='signal',sender='" DBUS_SERVICE_DBUS "',path='" DBUS_PATH_DBUS
      "',interface='" DBUS_INTERFACE_DBUS "',member='NameOwnerChanged'", &error);
  if (dbus_error_is_set(&error)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to subscribe to NameOwnerChanged: %s", error.message);
    dbus_error_free(&error);
    return 0;
  }
  if (!load_system_bus_id(conn)) return 0;
  if (!load_allow_callers(conn)) return 0;
  return save_allow_callers();
}

void ipwd_securityloader_cleanup(void) {
  while (allowed_callers != NULL) remove_caller(allowed_callers->name);
  free(system_bus_id);
  system_bus_id = NULL;
}

int ipwd_securityloader_authorize(DBusMessage *msg, DBusConnection *conn) {
  const char *sender = dbus_message_get_sender(msg);
  unsigned long uid, pid;
  if (sender == NULL || !get_uid_and_pid(conn, sender, &uid, &pid)) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Unable to identify DBus caller");
    return 0;
  }
  /*
   * lightdm invokes the IP-conflict check during the login phase, before a
   * user session is available, so it is allowed directly.
   */
  if (uid == 0 || caller_allowed(sender) || uid == allowed_user) return 1;
  ipwd_message(IPWD_MSG_TYPE_ALERT, "IP conflict check requested by unauthorized caller (UID %lu), access denied", uid);
  ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED,
      "Root privileges are required to request IP conflict checks");
  return 0;
}

int ipwd_securityloader_set_allow_caller(DBusMessage *msg, DBusConnection *conn) {
  DBusMessageIter args;
  const char *sender = dbus_message_get_sender(msg);
  const char *target;
  unsigned long sender_uid, sender_pid, target_uid, target_pid;
  if (sender == NULL || !dbus_message_iter_init(msg, &args) ||
      dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_INVALID_ARGS, "SetAllowCaller requires one DBus unique name");
    return 0;
  }
  dbus_message_iter_get_basic(&args, &target);
  if (target == NULL || target[0] != ':' || dbus_message_iter_next(&args)) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_INVALID_ARGS, "SetAllowCaller requires exactly one DBus unique name");
    return 0;
  }
  if (!get_uid_and_pid(conn, sender, &sender_uid, &sender_pid) ||
      !get_uid_and_pid(conn, target, &target_uid, &target_pid)) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Unable to identify DBus caller");
    return 0;
  }
  if (sender_uid != 0 && (loader_group == (gid_t)-1 || !process_in_group(sender_pid, loader_group) ||
      sender_uid != target_uid || !is_descendant(target_pid, sender_pid))) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "SetAllowCaller registrar is not allowed to authorize this caller");
    return 0;
  }
  if (!caller_allowed(target)) {
    if (!add_caller(target)) {
      ipwd_reply_error(msg, conn, DBUS_ERROR_NO_MEMORY, "Unable to register DBus caller");
      return 0;
    }
    if (!save_allow_callers()) {
      remove_caller(target);
      ipwd_reply_error(msg, conn, DBUS_ERROR_FAILED, "Unable to persist DBus caller registration");
      return 0;
    }
    ipwd_message(IPWD_MSG_TYPE_INFO, "Registered security-loader caller %s", target);
  }
  ipwd_reply_to_empty_method(msg, conn);
  return 1;
}

int ipwd_securityloader_get_allow_callers(DBusMessage *msg, DBusConnection *conn) {
  const char *sender = dbus_message_get_sender(msg);
  char **names = NULL;
  size_t count = 0, index;
  unsigned long uid, pid;
  if (sender == NULL || !get_uid_and_pid(conn, sender, &uid, &pid)) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Unable to identify DBus caller");
    return 0;
  }
  if (uid != 0) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Only root is allowed to call GetAllowCallers");
    return 0;
  }

  DBusMessage *reply;
  DBusMessageIter args, array;
  dbus_uint32_t serial = 0;

  reply = dbus_message_new_method_return(msg);
  if (reply == NULL) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    return 0;
  }

  dbus_message_iter_init_append(reply, &args);
  dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &array);

  names = sorted_caller_names(&count);
  if (count != 0 && names == NULL) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    dbus_message_unref(reply);
    return 0;
  }
  for (index = 0; index < count; index++) {
    const char *name = names[index];
    if (!dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &name)) {
      ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
      free(names);
      dbus_message_unref(reply);
      return 0;
    }
  }
  free(names);

  dbus_message_iter_close_container(&args, &array);

  if (!dbus_connection_send(conn, reply, &serial)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory\n");
    dbus_message_unref(reply);
    return 0;
  }
  dbus_connection_flush(conn);
  dbus_message_unref(reply);
  return 1;
}

void ipwd_securityloader_handle_name_owner_changed(DBusMessage *msg) {
  DBusMessageIter args;
  const char *sender = dbus_message_get_sender(msg);
  const char *name, *old_owner, *new_owner;
  if (!dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS, "NameOwnerChanged") ||
      sender == NULL || strcmp(sender, DBUS_SERVICE_DBUS) != 0 ||
      !dbus_message_has_path(msg, DBUS_PATH_DBUS)) return;
  if (!dbus_message_iter_init(msg, &args) || dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) return;
  dbus_message_iter_get_basic(&args, &name);
  if (!dbus_message_iter_next(&args) || dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) return;
  dbus_message_iter_get_basic(&args, &old_owner);
  if (!dbus_message_iter_next(&args) || dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) return;
  dbus_message_iter_get_basic(&args, &new_owner);
  if (name != NULL && name[0] == ':' && old_owner != NULL && old_owner[0] != '\0' && new_owner != NULL && new_owner[0] == '\0' &&
      remove_caller(name)) {
    save_allow_callers();
  }
}
