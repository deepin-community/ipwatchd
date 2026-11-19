#include "ipwatchd.h"
#include <polkit/polkit.h>

// Introspection XML data
static const char *introspection_xml =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node name=\"/com/deepin/system/IPWatchD\">\n"
"  <interface name=\"com.deepin.system.IPWatchD\">\n"
"    <method name=\"RequestIPConflictCheck\"><arg name=\"ip\" type=\"s\" direction=\"in\"/><arg name=\"interface\" type=\"s\" direction=\"in\"/><arg name=\"mac\" type=\"s\" direction=\"out\"/></method>\n"
"    <method name=\"SetAllowCaller\"><arg name=\"unique_name\" type=\"s\" direction=\"in\"/></method>\n"
"    <method name=\"GetAllowCallers\"><arg name=\"callers\" type=\"as\" direction=\"out\"/></method>\n"
"  </interface>\n"
"</node>\n";

// Introspection XML for the root object; it lists the child object that
// actually exposes the IPWatchD interface.
static const char *root_introspection_xml =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node>\n"
"  <node name=\"com\"/>\n"
"</node>\n";

// Introspection XML for the /com node; lists its direct child.
static const char *com_introspection_xml =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node name=\"/com\">\n"
"  <node name=\"deepin\"/>\n"
"</node>\n";

// Introspection XML for the /com/deepin node; lists its direct child.
static const char *deepin_introspection_xml =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node name=\"/com/deepin\">\n"
"  <node name=\"system\"/>\n"
"</node>\n";

// Introspection XML for the /com/deepin/system node; lists its direct child.
static const char *system_introspection_xml =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node name=\"/com/deepin/system\">\n"
"  <node name=\"IPWatchD\"/>\n"
"</node>\n";

void ipwd_send_signal(DBusConnection *conn, const char *ip, const char *smac, const char *dmac, int is_conflict) {
  DBusMessage *msg;
  dbus_uint32_t serial = 0;

  if (!conn) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "DBus connection is NULL");
    return;
  }

  // create a signal & check for errors
  msg = dbus_message_new_signal(
      "/com/deepin/system/IPWatchD",                                    // object name of the signal
      "com.deepin.system.IPWatchD",                                     // interface name of the signal
      is_conflict ? "IPConflict" : "IPConflictReslove");                // name of the signal
  if (NULL == msg) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Message Null");
    return;
  }

  // append arguments onto signal
  if (!dbus_message_append_args(msg,
      DBUS_TYPE_STRING, &ip,
      DBUS_TYPE_STRING, &smac,
      DBUS_TYPE_STRING, &dmac,
      DBUS_TYPE_INVALID)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    exit(1);
  }

  // send the message and flush the connection
  if (!dbus_connection_send(conn, msg, &serial)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    exit(1);
  }
  dbus_connection_flush(conn);

  // free the message
  if (msg != NULL)
    dbus_message_unref(msg);
}

void ipwd_reply_to_introspect(DBusMessage *msg, DBusConnection *conn) {
  DBusMessage *reply;
  DBusMessageIter args;
  dbus_uint32_t serial = 0;
  const char *xml_data = introspection_xml;
  const char *path = dbus_message_get_path(msg);

  if (path != NULL) {
    if (strcmp(path, "/") == 0) {
      xml_data = root_introspection_xml;
    } else if (strcmp(path, "/com") == 0) {
      xml_data = com_introspection_xml;
    } else if (strcmp(path, "/com/deepin") == 0) {
      xml_data = deepin_introspection_xml;
    } else if (strcmp(path, "/com/deepin/system") == 0) {
      xml_data = system_introspection_xml;
    }
  }

  // create a reply from the message
  reply = dbus_message_new_method_return(msg);
  if (!reply) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to create introspect reply");
    return;
  }

  dbus_message_iter_init_append(reply, &args);
  if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &xml_data)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    dbus_message_unref(reply);
    return;
  }

  // send the reply && flush the connection
  if (!dbus_connection_send(conn, reply, &serial)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to send introspect reply\n");
    dbus_message_unref(reply);
    return;
  }
  dbus_connection_flush(conn);

  ipwd_message(IPWD_MSG_TYPE_DEBUG, "Introspection data sent");

  // free the reply
  dbus_message_unref(reply);
}

void ipwd_reply_to_method(DBusMessage *msg, DBusConnection *conn, const char *mac) {
  DBusMessage* reply;
  DBusMessageIter args;
  dbus_uint32_t serial = 0;

  // create a reply from the message
  reply = dbus_message_new_method_return(msg);
  if (reply == NULL) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to create method reply");
    /* Try to send an error reply (note: dbus_message_new_error may also fail under OOM) */
    ipwd_reply_error(msg, conn, DBUS_ERROR_FAILED, "Failed to create method reply");
    return;
  }

  dbus_message_iter_init_append(reply, &args);
  if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &mac)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    exit(1);
  }

  // send the reply && flush the connection
  if (!dbus_connection_send(conn, reply, &serial)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory\n");
    exit(1);
  }
  dbus_connection_flush(conn);

  // free the reply
  dbus_message_unref(reply);
}

void ipwd_reply_to_empty_method(DBusMessage *msg, DBusConnection *conn) {
  DBusMessage *reply = dbus_message_new_method_return(msg);
  dbus_uint32_t serial = 0;
  if (reply == NULL) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to create method reply");
    return;
  }
  if (!dbus_connection_send(conn, reply, &serial)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to send method reply");
  }
  dbus_connection_flush(conn);
  dbus_message_unref(reply);
}

/**
 * Sends an error reply for a DBus method call.
 *
 * msg is the method call being rejected, conn is the system bus connection,
 * name is the DBus error name, and message is the human-readable error text.
 */
void ipwd_reply_error(DBusMessage *msg, DBusConnection *conn, const char *name, const char *message) {
  DBusMessage *reply;
  dbus_uint32_t serial = 0;

  reply = dbus_message_new_error(msg, name, message);
  if (reply == NULL) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to create DBus error reply");
    return;
  }

  if (!dbus_connection_send(conn, reply, &serial)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to send DBus error reply");
    dbus_message_unref(reply);
    return;
  }

  dbus_connection_flush(conn);
  dbus_message_unref(reply);
}

/**
 * Checks whether the DBus sender is allowed to request an IP conflict check.
 *
 * Root senders are allowed directly. Other senders are checked with polkit
 * against IPWD_POLKIT_ACTION_REQUEST_IP_CONFLICT_CHECK. Returns 1 when the
 * caller is authorized and 0 when authorization fails or cannot be checked.
 */
int ipwd_dbus_check_authorization(DBusMessage *msg, DBusConnection *conn) {
  const char *sender;
  DBusError dbus_err;
  unsigned long sender_uid;
  PolkitAuthority *authority = NULL;
  PolkitSubject *subject = NULL;
  PolkitAuthorizationResult *result = NULL;
  GError *error = NULL;
  int authorized = 0;

  sender = dbus_message_get_sender(msg);
  if (sender == NULL) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Missing DBus sender");
    return 0;
  }

  dbus_error_init(&dbus_err);
  sender_uid = dbus_bus_get_unix_user(conn, sender, &dbus_err);
  if (!dbus_error_is_set(&dbus_err) && sender_uid == 0) {
    return 1;
  }
  if (dbus_error_is_set(&dbus_err)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to get unix user for %s: %s", sender, dbus_err.message);
    dbus_error_free(&dbus_err);
  }

  authority = polkit_authority_get_sync(NULL, &error);
  if (authority == NULL) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to get polkit authority: %s", error ? error->message : "unknown error");
    if (error != NULL) {
      g_error_free(error);
    }
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Authorization service is unavailable");
    return 0;
  }

  subject = polkit_system_bus_name_new(sender);
  if (subject == NULL) {
    g_object_unref(authority);
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Unable to create authorization subject");
    return 0;
  }

  result = polkit_authority_check_authorization_sync(
      authority,
      subject,
      IPWD_POLKIT_ACTION_REQUEST_IP_CONFLICT_CHECK,
      NULL,
      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
      NULL,
      &error);

  if (result != NULL) {
    authorized = polkit_authorization_result_get_is_authorized(result);
  }

  if (error != NULL) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "polkit authorization check failed: %s", error->message);
    g_error_free(error);
  }

  if (result != NULL) {
    g_object_unref(result);
  }
  g_object_unref(subject);
  g_object_unref(authority);

  if (!authorized) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Not authorized to request IP conflict checks");
  }

  return authorized;
}
