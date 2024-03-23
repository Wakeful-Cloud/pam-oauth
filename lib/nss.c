/**
 * This NSS module returns a stub passwd entry to work around the following bug:
 * * https://www.linuxquestions.org/questions/programming-9/can%27t-get-auth-token-for-non-local-users-with-pam-module-945164/
 *
 * Based on: https://github.com/cinek810/libnss-pool/blob/20fbb7c96ed330539fa7bdc81fb9f04155d72401/libnss_pool.c
 */

#define _GNU_SOURCE

/**
 * @brief Debug mode
 */
#define DEBUG_MODE false

#include <nss.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if DEBUG_MODE == true
/**
 * @brief Log a message to a file
 * @param format Format string
 * @param ... Arguments
 */
static void debug(const char *format, ...)
{
  // Open the log file
  FILE *log = fopen("/var/log/pam-oauth-nss.log", "a");

  // Write the log message
  va_list args;
  va_start(args, format);
  vfprintf(log, format, args);
  va_end(args);

  // Close the log file
  fclose(log);
}
#else
/**
 * @brief Log a message to a file
 * @param format Format string
 * @param ... Arguments
 */
#define debug(...)
#endif

/**
 * @brief Check if the process is running as a specific name
 * @param name Process name
 * @return `true` if the process is running as the specified name, `false` otherwise
 */
static bool running_as(const char *name)
{
  // Get the process ID
  pid_t pid = getpid();

  // Get the process executable
  char exe_proc_path[1024];
  snprintf(exe_proc_path, sizeof(exe_proc_path), "/proc/%d/exe", pid);

  // Read the link
  char exe_path[1024];
  ssize_t exe_path_len = readlink(exe_proc_path, exe_path, sizeof(exe_path) - 1);

  // Null-terminate the string
  exe_path[exe_path_len] = '\0';

  // Get the base name
  char *base_exe_name = basename(exe_path);

  // Check if the process is running as the specified name
  bool result = strcmp(base_exe_name, name) == 0;

  // Debug log
  debug("PID: %d, executable path: %s, executable name: %s (want: %s), match: %s\n", pid, exe_path, base_exe_name, name, result ? "true" : "false");

  return result;
}

/**
 * @brief Set a passwd entry to the PAM OAuth stub user
 * @param result Pointer to buffer where the result is stored
 * @param buffer Pointer to a buffer where the function can store additional data for the result etc
 * @param buflen Length of the buffer pointed to by `buffer`
 * @return Status (One of `NSS_STATUS_TRYAGAIN`, `NSS_STATUS_UNAVAIL`, `NSS_STATUS_NOTFOUND`, or `NSS_STATUS_SUCCESS`)
 */
static enum nss_status set_stub(struct passwd *result, char *buffer, size_t buflen)
{
  result->pw_name = "pam-oauth-stub";
  result->pw_passwd = "*";
  result->pw_uid = 2380747560;
  result->pw_gid = 2380747560;
  result->pw_gecos = "PAM OAuth Stub";
  result->pw_dir = "/";
  result->pw_shell = "/usr/bin/pam-oauth-login";

  return NSS_STATUS_SUCCESS;
}

/**
 * @brief Get a passwd entry by name
 * @param name User name
 * @param result Pointer to buffer where the result is stored
 * @param buffer Pointer to a buffer where the function can store additional data for the result etc
 * @param buflen Length of the buffer pointed to by `buffer`
 * @param errnop The low-level error code to return to the application. If the return value is not `NSS_STATUS_SUCCESS`, `*errnop` needs to be set to a non-zero value. An NSS module should never set `*errnop` to zero. The value `ERANGE` is special
 * @return Status (One of `NSS_STATUS_TRYAGAIN`, `NSS_STATUS_UNAVAIL`, `NSS_STATUS_NOTFOUND`, or `NSS_STATUS_SUCCESS`)
 */
enum nss_status _nss_oauth_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
  // Check if running as SSH daemon
  if (!running_as("sshd"))
  {
    return NSS_STATUS_NOTFOUND;
  }

  // Set the result to the stub user
  return set_stub(result, buffer, buflen);
}

/**
 * @brief Get a passwd entry by UID
 * @param uid User ID
 * @param result Pointer to buffer where the result is stored
 * @param buffer Pointer to a buffer where the function can store additional data for the result etc
 * @param buflen Length of the buffer pointed to by `buffer`
 * @param errnop The low-level error code to return to the application. If the return value is not `NSS_STATUS_SUCCESS`, `*errnop` needs to be set to a non-zero value. An NSS module should never set `*errnop` to zero. The value `ERANGE` is special
 * @return Status (One of `NSS_STATUS_TRYAGAIN`, `NSS_STATUS_UNAVAIL`, `NSS_STATUS_NOTFOUND`, or `NSS_STATUS_SUCCESS`)
 */
enum nss_status _nss_oauth_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
  // Check if running as SSH daemon
  if (!running_as("sshd"))
  {
    return NSS_STATUS_NOTFOUND;
  }

  // Set the result to the stub user
  return set_stub(result, buffer, buflen);
}