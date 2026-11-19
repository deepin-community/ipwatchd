/* SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd. */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _GNU_SOURCE
#define IPWD_SECURITY_LOADER_TEST

#include <limits.h>

#include "../src/securityloader.c"

static unsigned int tests_run;
static unsigned int tests_failed;
static unsigned int reply_error_count;
static const char *last_reply_error_name;

#define EXPECT_TRUE(expression)                                                     \
  do {                                                                              \
    if (!(expression)) {                                                            \
      fprintf(stderr, "%s:%d: expectation failed: %s\n", __FILE__, __LINE__,       \
          #expression);                                                             \
      return 0;                                                                     \
    }                                                                               \
  } while (0)

#define EXPECT_STRING(actual, expected)                                             \
  do {                                                                              \
    const char *actual_value = (actual);                                             \
    const char *expected_value = (expected);                                         \
    if (actual_value == NULL || strcmp(actual_value, expected_value) != 0) {         \
      fprintf(stderr, "%s:%d: expected \"%s\", got \"%s\"\n", __FILE__,          \
          __LINE__, expected_value, actual_value == NULL ? "(null)" : actual_value); \
      return 0;                                                                     \
    }                                                                               \
  } while (0)

#define EXPECT_TRUE_OR_GOTO(expression, label)                                      \
  do {                                                                              \
    if (!(expression)) {                                                            \
      fprintf(stderr, "%s:%d: expectation failed: %s\n", __FILE__, __LINE__,       \
          #expression);                                                             \
      goto label;                                                                   \
    }                                                                               \
  } while (0)

void ipwd_message(IPWD_MSG_TYPE type, const char *format, ...) {
  (void)type;
  (void)format;
}

void ipwd_reply_error(DBusMessage *msg, DBusConnection *conn, const char *name,
    const char *message) {
  (void)msg;
  (void)conn;
  reply_error_count++;
  last_reply_error_name = name;
  (void)message;
}

void ipwd_reply_to_empty_method(DBusMessage *msg, DBusConnection *conn) {
  (void)msg;
  (void)conn;
}

int ipwd_dbus_check_authorization(DBusMessage *msg, DBusConnection *conn) {
  ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Not authorized");
  (void)conn;
  return 0;
}

static void reset_fixture(void) {
  ipwd_securityloader_cleanup();
  loader_group = (gid_t)-1;
  allowed_user = (uid_t)-1;
  reply_error_count = 0;
  last_reply_error_name = NULL;
  unlink(IPWD_SECURITY_LOADER_STATE_FILE);
  rmdir(IPWD_SECURITY_LOADER_STATE_DIR);
  unlink(IPWD_SECURITY_LOADER_STATE_DIR);
}

static void clear_allowed_callers(void) {
  while (allowed_callers != NULL) remove_caller(allowed_callers->name);
}

static int write_state(const char *bus_id, const char *const *names,
    size_t count) {
  struct json_object *state = NULL;
  struct json_object *scopes = NULL;
  struct json_object *callers = NULL;
  size_t index;
  int result = 0;

  if (!ensure_state_directory()) return 0;
  state = json_object_new_object();
  scopes = json_object_new_object();
  callers = json_object_new_array();
  if (state == NULL || scopes == NULL || callers == NULL) goto out;

  json_object_object_add(state, "busId", json_object_new_string(bus_id));
  for (index = 0; index < count; index++) {
    struct json_object *caller = json_object_new_string(names[index]);
    if (caller == NULL || json_object_array_add(callers, caller) != 0) {
      if (caller != NULL) json_object_put(caller);
      goto out;
    }
  }
  json_object_object_add(scopes, IPWD_SECURITY_LOADER_SCOPE, callers);
  callers = NULL;
  json_object_object_add(state, "callers", scopes);
  scopes = NULL;

  if (json_object_to_file_ext(IPWD_SECURITY_LOADER_STATE_FILE, state,
          JSON_C_TO_STRING_PLAIN) != 0 ||
      chmod(IPWD_SECURITY_LOADER_STATE_FILE, 0600) != 0) {
    goto out;
  }
  result = 1;

out:
  if (callers != NULL) json_object_put(callers);
  if (scopes != NULL) json_object_put(scopes);
  if (state != NULL) json_object_put(state);
  return result;
}

static int write_all(int fd, const void *data, size_t size) {
  const char *current = data;

  while (size > 0) {
    ssize_t written = write(fd, current, size);
    if (written < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    current += written;
    size -= (size_t)written;
  }
  return 1;
}

static int read_all(int fd, void *data, size_t size) {
  char *current = data;

  while (size > 0) {
    ssize_t received = read(fd, current, size);
    if (received < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    if (received == 0) return 0;
    current += received;
    size -= (size_t)received;
  }
  return 1;
}

static int write_raw_state(const char *content, mode_t mode) {
  int fd;
  int result;

  if (!ensure_state_directory()) return 0;
  fd = open(IPWD_SECURITY_LOADER_STATE_FILE,
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return 0;
  result = write_all(fd, content, strlen(content)) && fchmod(fd, mode) == 0;
  if (close(fd) != 0) result = 0;
  return result;
}

static DBusConnection *open_session_bus(void) {
  DBusConnection *connection;
  DBusError error;

  dbus_error_init(&error);
  connection = dbus_bus_get_private(DBUS_BUS_SESSION, &error);
  if (connection == NULL) {
    fprintf(stderr, "unable to connect to session bus: %s\n",
        dbus_error_is_set(&error) ? error.message : "unknown error");
  } else {
    dbus_connection_set_exit_on_disconnect(connection, FALSE);
  }
  if (dbus_error_is_set(&error)) dbus_error_free(&error);
  return connection;
}

static void close_bus(DBusConnection *connection) {
  if (connection == NULL) return;
  dbus_connection_close(connection);
  dbus_connection_unref(connection);
}

static int bus_name_has_owner(DBusConnection *connection, const char *name) {
  DBusError error;
  dbus_bool_t has_owner;

  dbus_error_init(&error);
  has_owner = dbus_bus_name_has_owner(connection, name, &error);
  if (dbus_error_is_set(&error)) {
    fprintf(stderr, "unable to query owner for %s: %s\n", name, error.message);
    dbus_error_free(&error);
    return -1;
  }
  return has_owner ? 1 : 0;
}

static DBusMessage *new_name_owner_changed(const char *sender, const char *path,
    const char *interface, const char *member, const char *name,
    const char *old_owner, const char *new_owner) {
  DBusMessage *message = dbus_message_new_signal(path, interface, member);
  if (message == NULL) return NULL;
  if (!dbus_message_set_sender(message, sender) ||
      !dbus_message_append_args(message,
          DBUS_TYPE_STRING, &name,
          DBUS_TYPE_STRING, &old_owner,
          DBUS_TYPE_STRING, &new_owner,
          DBUS_TYPE_INVALID)) {
    dbus_message_unref(message);
    return NULL;
  }
  return message;
}

static int test_state_directory_mode_ignores_umask(void) {
  struct stat status;
  mode_t previous_umask;
  int result;

  previous_umask = umask(0166);
  result = ensure_state_directory();
  umask(previous_umask);

  EXPECT_TRUE(result);
  EXPECT_TRUE(stat(IPWD_SECURITY_LOADER_STATE_DIR, &status) == 0);
  EXPECT_TRUE(S_ISDIR(status.st_mode));
  EXPECT_TRUE(status.st_uid == geteuid());
  EXPECT_TRUE((status.st_mode & 0777) == 0700);
  return 1;
}

static int test_restore_requires_matching_bus_id_and_live_caller(void) {
  DBusConnection *daemon_connection = NULL;
  DBusConnection *caller_connection = NULL;
  const char *caller_name;
  const char *names[1];
  char *bus_id;

  daemon_connection = open_session_bus();
  EXPECT_TRUE(daemon_connection != NULL);
  caller_connection = open_session_bus();
  EXPECT_TRUE(caller_connection != NULL);
  caller_name = dbus_bus_get_unique_name(caller_connection);
  EXPECT_TRUE(caller_name != NULL);
  names[0] = caller_name;

  EXPECT_TRUE(load_system_bus_id(daemon_connection));
  EXPECT_TRUE(system_bus_id != NULL && system_bus_id[0] != '\0');
  bus_id = strdup(system_bus_id);
  EXPECT_TRUE(bus_id != NULL);
  EXPECT_TRUE(write_state(bus_id, names, 1));
  ipwd_securityloader_cleanup();

  EXPECT_TRUE(ipwd_securityloader_init(daemon_connection));
  EXPECT_TRUE(caller_allowed(caller_name));

  clear_allowed_callers();
  EXPECT_TRUE(write_state("a-different-dbus-instance", names, 1));
  EXPECT_TRUE(load_allow_callers(daemon_connection));
  EXPECT_TRUE(!caller_allowed(caller_name));

  free(bus_id);
  close_bus(caller_connection);
  close_bus(daemon_connection);
  return 1;
}

static int test_invalid_state_is_ignored(void) {
  system_bus_id = strdup("test-bus-id");
  EXPECT_TRUE(system_bus_id != NULL);
  EXPECT_TRUE(write_raw_state("{ this is not JSON", 0600));
  EXPECT_TRUE(load_allow_callers(NULL));
  EXPECT_TRUE(allowed_callers == NULL);
  return 1;
}

static int test_oversized_state_is_rejected(void) {
  int fd;

  system_bus_id = strdup("test-bus-id");
  EXPECT_TRUE(system_bus_id != NULL);
  EXPECT_TRUE(ensure_state_directory());
  fd = open(IPWD_SECURITY_LOADER_STATE_FILE,
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  EXPECT_TRUE(fd >= 0);
  EXPECT_TRUE(ftruncate(fd, IPWD_SECURITY_LOADER_MAX_STATE_SIZE + 1) == 0);
  EXPECT_TRUE(close(fd) == 0);
  EXPECT_TRUE(!load_allow_callers(NULL));
  EXPECT_TRUE(allowed_callers == NULL);
  return 1;
}

static int test_state_with_unsafe_permissions_is_rejected(void) {
  system_bus_id = strdup("test-bus-id");
  EXPECT_TRUE(system_bus_id != NULL);
  EXPECT_TRUE(write_raw_state("{}", 0644));
  EXPECT_TRUE(!load_allow_callers(NULL));
  EXPECT_TRUE(allowed_callers == NULL);
  return 1;
}

static int test_disconnected_unique_name_is_not_restored(void) {
  DBusConnection *daemon_connection = NULL;
  DBusConnection *caller_connection = NULL;
  char *caller_name;
  const char *names[1];
  int has_owner = 1;
  unsigned int attempt;

  daemon_connection = open_session_bus();
  EXPECT_TRUE(daemon_connection != NULL);
  caller_connection = open_session_bus();
  EXPECT_TRUE(caller_connection != NULL);
  caller_name = strdup(dbus_bus_get_unique_name(caller_connection));
  EXPECT_TRUE(caller_name != NULL);
  close_bus(caller_connection);

  for (attempt = 0; attempt < 100; attempt++) {
    has_owner = bus_name_has_owner(daemon_connection, caller_name);
    if (has_owner <= 0) break;
    usleep(1000);
  }
  EXPECT_TRUE(has_owner == 0);
  EXPECT_TRUE(load_system_bus_id(daemon_connection));
  names[0] = caller_name;
  EXPECT_TRUE(write_state(system_bus_id, names, 1));
  EXPECT_TRUE(load_allow_callers(daemon_connection));
  EXPECT_TRUE(!caller_allowed(caller_name));

  free(caller_name);
  close_bus(daemon_connection);
  return 1;
}

static int test_duplicate_caller_is_restored_once(void) {
  DBusConnection *daemon_connection = NULL;
  DBusConnection *caller_connection = NULL;
  const char *caller_name;
  const char *names[2];
  char **restored_names;
  size_t restored_count;

  daemon_connection = open_session_bus();
  EXPECT_TRUE(daemon_connection != NULL);
  caller_connection = open_session_bus();
  EXPECT_TRUE(caller_connection != NULL);
  caller_name = dbus_bus_get_unique_name(caller_connection);
  EXPECT_TRUE(caller_name != NULL);
  names[0] = caller_name;
  names[1] = caller_name;

  EXPECT_TRUE(load_system_bus_id(daemon_connection));
  EXPECT_TRUE(write_state(system_bus_id, names, 2));
  EXPECT_TRUE(load_allow_callers(daemon_connection));
  restored_names = sorted_caller_names(&restored_count);
  EXPECT_TRUE(restored_names != NULL);
  EXPECT_TRUE(restored_count == 1);
  EXPECT_STRING(restored_names[0], caller_name);
  free(restored_names);

  close_bus(caller_connection);
  close_bus(daemon_connection);
  return 1;
}

typedef struct TEST_CHILD_CALLER {
  pid_t pid;
  int release_fd;
  char name[256];
} TEST_CHILD_CALLER;

typedef struct TEST_CHILD_READY {
  int ready;
  char name[256];
} TEST_CHILD_READY;

static int start_child_caller(TEST_CHILD_CALLER *child) {
  int ready_pipe[2] = {-1, -1};
  int release_pipe[2] = {-1, -1};
  pid_t pid;

  memset(child, 0, sizeof(*child));
  child->pid = -1;
  child->release_fd = -1;
  if (pipe(ready_pipe) != 0 || pipe(release_pipe) != 0) goto error;
  pid = fork();
  if (pid < 0) goto error;
  if (pid == 0) {
    TEST_CHILD_READY result = {0};
    DBusConnection *connection;
    char release;

    close(ready_pipe[0]);
    close(release_pipe[1]);
    connection = open_session_bus();
    if (connection != NULL) {
      const char *name = dbus_bus_get_unique_name(connection);
      if (name != NULL && strlen(name) < sizeof(result.name)) {
        result.ready = 1;
        strcpy(result.name, name);
      }
    }
    if (!write_all(ready_pipe[1], &result, sizeof(result))) result.ready = 0;
    close(ready_pipe[1]);
    if (result.ready) (void)read(release_pipe[0], &release, 1);
    close(release_pipe[0]);
    close_bus(connection);
    _exit(result.ready ? 0 : 1);
  }

  close(ready_pipe[1]);
  ready_pipe[1] = -1;
  close(release_pipe[0]);
  release_pipe[0] = -1;
  TEST_CHILD_READY result;
  if (!read_all(ready_pipe[0], &result, sizeof(result)) || !result.ready) {
    close(ready_pipe[0]);
    close(release_pipe[1]);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    return 0;
  }
  close(ready_pipe[0]);
  child->pid = pid;
  child->release_fd = release_pipe[1];
  strcpy(child->name, result.name);
  return 1;

error:
  if (ready_pipe[0] >= 0) close(ready_pipe[0]);
  if (ready_pipe[1] >= 0) close(ready_pipe[1]);
  if (release_pipe[0] >= 0) close(release_pipe[0]);
  if (release_pipe[1] >= 0) close(release_pipe[1]);
  return 0;
}

static void stop_child_caller(TEST_CHILD_CALLER *child) {
  if (child->release_fd >= 0) {
    close(child->release_fd);
    child->release_fd = -1;
  }
  if (child->pid > 0) {
    while (waitpid(child->pid, NULL, 0) < 0 && errno == EINTR) {}
    child->pid = -1;
  }
}

static int test_set_allow_caller_rolls_back_when_save_fails(void) {
  TEST_CHILD_CALLER child = {.pid = -1, .release_fd = -1};
  DBusConnection *registrar_connection = NULL;
  DBusMessage *message = NULL;
  const char *registrar_name;
  const char *target;
  int state_fd = -1;
  int passed = 0;

  EXPECT_TRUE_OR_GOTO(start_child_caller(&child), out);
  registrar_connection = open_session_bus();
  EXPECT_TRUE_OR_GOTO(registrar_connection != NULL, out);
  registrar_name = dbus_bus_get_unique_name(registrar_connection);
  EXPECT_TRUE_OR_GOTO(registrar_name != NULL, out);
  EXPECT_TRUE_OR_GOTO(load_system_bus_id(registrar_connection), out);

  loader_group = getgid();
  state_fd = open(IPWD_SECURITY_LOADER_STATE_DIR,
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  EXPECT_TRUE_OR_GOTO(state_fd >= 0, out);
  EXPECT_TRUE_OR_GOTO(close(state_fd) == 0, out);
  state_fd = -1;

  message = dbus_message_new_method_call(IPWD_DBUS_SERVICE, IPWD_DBUS_PATH,
      IPWD_DBUS_SERVICE, "SetAllowCaller");
  EXPECT_TRUE_OR_GOTO(message != NULL, out);
  target = child.name;
  EXPECT_TRUE_OR_GOTO(dbus_message_set_sender(message, registrar_name), out);
  EXPECT_TRUE_OR_GOTO(dbus_message_append_args(message,
      DBUS_TYPE_STRING, &target, DBUS_TYPE_INVALID), out);

  EXPECT_TRUE_OR_GOTO(!ipwd_securityloader_set_allow_caller(message,
      registrar_connection), out);
  EXPECT_TRUE_OR_GOTO(!caller_allowed(child.name), out);
  EXPECT_TRUE_OR_GOTO(reply_error_count == 1, out);
  EXPECT_TRUE_OR_GOTO(last_reply_error_name != NULL &&
      strcmp(last_reply_error_name, DBUS_ERROR_FAILED) == 0, out);
  passed = 1;

out:
  if (state_fd >= 0) close(state_fd);
  if (message != NULL) dbus_message_unref(message);
  close_bus(registrar_connection);
  stop_child_caller(&child);
  return passed;
}

static int test_name_owner_changed_requires_real_bus_sender(void) {
  const char *caller = ":1.4242";
  DBusMessage *message;
  struct json_object *state;
  struct json_object *scopes;
  struct json_object *callers;

  system_bus_id = strdup("test-bus-id");
  EXPECT_TRUE(system_bus_id != NULL);
  EXPECT_TRUE(add_caller(caller));
  EXPECT_TRUE(save_allow_callers());

  message = new_name_owner_changed(":1.9999", DBUS_PATH_DBUS,
      DBUS_INTERFACE_DBUS, "NameOwnerChanged", caller, caller, "");
  EXPECT_TRUE(message != NULL);
  ipwd_securityloader_handle_name_owner_changed(message);
  dbus_message_unref(message);
  EXPECT_TRUE(caller_allowed(caller));

  message = new_name_owner_changed(DBUS_SERVICE_DBUS, "/com/example/Fake",
      DBUS_INTERFACE_DBUS, "NameOwnerChanged", caller, caller, "");
  EXPECT_TRUE(message != NULL);
  ipwd_securityloader_handle_name_owner_changed(message);
  dbus_message_unref(message);
  EXPECT_TRUE(caller_allowed(caller));

  message = new_name_owner_changed(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      "com.example.Fake", "NameOwnerChanged", caller, caller, "");
  EXPECT_TRUE(message != NULL);
  ipwd_securityloader_handle_name_owner_changed(message);
  dbus_message_unref(message);
  EXPECT_TRUE(caller_allowed(caller));

  message = new_name_owner_changed(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      DBUS_INTERFACE_DBUS, "FakeOwnerChanged", caller, caller, "");
  EXPECT_TRUE(message != NULL);
  ipwd_securityloader_handle_name_owner_changed(message);
  dbus_message_unref(message);
  EXPECT_TRUE(caller_allowed(caller));

  message = new_name_owner_changed(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      DBUS_INTERFACE_DBUS, "NameOwnerChanged", caller, caller, "");
  EXPECT_TRUE(message != NULL);
  ipwd_securityloader_handle_name_owner_changed(message);
  dbus_message_unref(message);
  EXPECT_TRUE(!caller_allowed(caller));

  state = json_object_from_file(IPWD_SECURITY_LOADER_STATE_FILE);
  EXPECT_TRUE(state != NULL);
  EXPECT_TRUE(json_object_object_get_ex(state, "callers", &scopes));
  EXPECT_TRUE(json_object_object_get_ex(scopes, IPWD_SECURITY_LOADER_SCOPE,
      &callers));
  EXPECT_TRUE(json_object_is_type(callers, json_type_array));
  EXPECT_TRUE(json_object_array_length(callers) == 0);
  json_object_put(state);
  return 1;
}

static int test_saved_json_has_expected_structure_and_sorted_callers(void) {
  static const char *const expected[] = {":1.10", ":1.20", ":1.3"};
  struct json_object *state;
  struct json_object *bus_id;
  struct json_object *scopes;
  struct json_object *callers;
  size_t index;

  system_bus_id = strdup("test-bus-id");
  EXPECT_TRUE(system_bus_id != NULL);
  EXPECT_TRUE(add_caller(":1.3"));
  EXPECT_TRUE(add_caller(":1.10"));
  EXPECT_TRUE(add_caller(":1.20"));
  EXPECT_TRUE(save_allow_callers());

  state = json_object_from_file(IPWD_SECURITY_LOADER_STATE_FILE);
  EXPECT_TRUE(state != NULL);
  EXPECT_TRUE(json_object_is_type(state, json_type_object));
  EXPECT_TRUE(json_object_object_length(state) == 2);
  EXPECT_TRUE(json_object_object_get_ex(state, "busId", &bus_id));
  EXPECT_TRUE(json_object_is_type(bus_id, json_type_string));
  EXPECT_STRING(json_object_get_string(bus_id), "test-bus-id");
  EXPECT_TRUE(json_object_object_get_ex(state, "callers", &scopes));
  EXPECT_TRUE(json_object_is_type(scopes, json_type_object));
  EXPECT_TRUE(json_object_object_length(scopes) == 1);
  EXPECT_TRUE(json_object_object_get_ex(scopes, IPWD_SECURITY_LOADER_SCOPE,
      &callers));
  EXPECT_TRUE(json_object_is_type(callers, json_type_array));
  EXPECT_TRUE(json_object_array_length(callers) == 3);
  for (index = 0; index < 3; index++) {
    struct json_object *caller = json_object_array_get_idx(callers, index);
    EXPECT_TRUE(caller != NULL && json_object_is_type(caller, json_type_string));
    EXPECT_STRING(json_object_get_string(caller), expected[index]);
  }
  json_object_put(state);
  return 1;
}

static int test_authorize_allows_allowed_user(void) {
  DBusConnection *conn = NULL;
  DBusMessage *msg = NULL;
  const char *sender;
  int passed = 0;

  conn = open_session_bus();
  EXPECT_TRUE_OR_GOTO(conn != NULL, out);
  sender = dbus_bus_get_unique_name(conn);
  EXPECT_TRUE_OR_GOTO(sender != NULL, out);
  EXPECT_TRUE_OR_GOTO(load_system_bus_id(conn), out);

  msg = dbus_message_new_method_call(IPWD_DBUS_SERVICE, IPWD_DBUS_PATH,
      IPWD_DBUS_SERVICE, "RequestIPConflictCheck");
  EXPECT_TRUE_OR_GOTO(msg != NULL, out);
  EXPECT_TRUE_OR_GOTO(dbus_message_set_sender(msg, sender), out);

  allowed_user = getuid();
  EXPECT_TRUE_OR_GOTO(ipwd_securityloader_authorize(msg, conn) == 1, out);
  EXPECT_TRUE_OR_GOTO(reply_error_count == 0, out);
  passed = 1;

out:
  if (msg != NULL) dbus_message_unref(msg);
  close_bus(conn);
  return passed;
}

static int test_authorize_denies_when_user_not_allowed(void) {
  DBusConnection *conn = NULL;
  DBusMessage *msg = NULL;
  const char *sender;
  int passed = 0;

  if (getuid() == 0) return 1;

  conn = open_session_bus();
  EXPECT_TRUE_OR_GOTO(conn != NULL, out);
  sender = dbus_bus_get_unique_name(conn);
  EXPECT_TRUE_OR_GOTO(sender != NULL, out);
  EXPECT_TRUE_OR_GOTO(load_system_bus_id(conn), out);

  msg = dbus_message_new_method_call(IPWD_DBUS_SERVICE, IPWD_DBUS_PATH,
      IPWD_DBUS_SERVICE, "RequestIPConflictCheck");
  EXPECT_TRUE_OR_GOTO(msg != NULL, out);
  EXPECT_TRUE_OR_GOTO(dbus_message_set_sender(msg, sender), out);

  EXPECT_TRUE_OR_GOTO(ipwd_securityloader_authorize(msg, conn) == 0, out);
  EXPECT_TRUE_OR_GOTO(reply_error_count == 1, out);
  passed = 1;

out:
  if (msg != NULL) dbus_message_unref(msg);
  close_bus(conn);
  return passed;
}

static void run_test(const char *name, int (*test)(void)) {
  int passed;

  reset_fixture();
  tests_run++;
  passed = test();
  if (!passed) tests_failed++;
  fprintf(stderr, "%s: %s\n", passed ? "PASS" : "FAIL", name);
  reset_fixture();
}

int main(void) {
  char original_directory[PATH_MAX];
  char temporary_directory[] = "/tmp/ipwatchd-securityloader-test.XXXXXX";
  char *test_directory;

  if (getcwd(original_directory, sizeof(original_directory)) == NULL) {
    perror("getcwd");
    return 1;
  }
  test_directory = mkdtemp(temporary_directory);
  if (test_directory == NULL || chdir(test_directory) != 0) {
    perror("create test directory");
    return 1;
  }

  run_test("state directory is 0700 under restrictive umask",
      test_state_directory_mode_ignores_umask);
  run_test("only live callers from the current bus are restored",
      test_restore_requires_matching_bus_id_and_live_caller);
  run_test("invalid JSON is ignored safely",
      test_invalid_state_is_ignored);
  run_test("state files larger than 1 MiB are rejected",
      test_oversized_state_is_rejected);
  run_test("state files with unsafe permissions are rejected",
      test_state_with_unsafe_permissions_is_rejected);
  run_test("disconnected unique names are not restored",
      test_disconnected_unique_name_is_not_restored);
  run_test("duplicate callers are restored only once",
      test_duplicate_caller_is_restored_once);
  run_test("SetAllowCaller rolls back after a save failure",
      test_set_allow_caller_rolls_back_when_save_fails);
  run_test("NameOwnerChanged must originate from the D-Bus daemon",
      test_name_owner_changed_requires_real_bus_sender);
  run_test("saved JSON is scoped and callers are sorted",
      test_saved_json_has_expected_structure_and_sorted_callers);
  run_test("authorize allows the allowed user",
      test_authorize_allows_allowed_user);
  run_test("authorize denies when user is not allowed",
      test_authorize_denies_when_user_not_allowed);

  reset_fixture();
  if (chdir(original_directory) != 0 || rmdir(test_directory) != 0) {
    perror("remove test directory");
    return 1;
  }
  fprintf(stderr, "%u tests, %u failures\n", tests_run, tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
