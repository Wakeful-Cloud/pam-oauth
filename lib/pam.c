/**
 * This PAM module executes the client executable to work around the following bug:
 * https://github.com/duosecurity/duo_unix/issues/73
 * https://bugzilla.mindrot.org/show_bug.cgi?id=2876
 * https://github.com/openssh/openssh-portable/pull/337
 * https://github.com/openssh/openssh-portable/pull/452
 *
 * Communication with the client executable is done through stdin and stdout and is JSON-encoded.
 *
 * Based on: https://github.com/linux-pam/linux-pam/blob/1e2c6cecf81dcaeea0c2c9d37bc35eea120cd77d/modules/pam_exec/pam_exec.c
 */

#define _GNU_SOURCE

/**
 * @brief Debug mode
 */
#define DEBUG_MODE false

#include <errno.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "json/json.h"

#if DEBUG_MODE == true
/**
 * @brief Log a message to a file
 * @param format Format string
 * @param ... Arguments
 */
#define debug(...) fprintf(stderr, __VA_ARGS__)
#else
/**
 * @brief Log a message to a file
 * @param format Format string
 * @param ... Arguments
 */
#define debug(...)
#endif

#define ENV_ITEM(n) \
  {                 \
    (n), #n         \
  }

/**
 * @brief Custom environment items
 */
static struct
{
  int item;
  const char *name;
} env_items[] = {
    ENV_ITEM(PAM_SERVICE),
    ENV_ITEM(PAM_USER),
    ENV_ITEM(PAM_TTY),
    ENV_ITEM(PAM_RHOST),
    ENV_ITEM(PAM_RUSER),
};

/**
 * @brief Custom environment items length
 */
static int env_items_length = sizeof(env_items) / sizeof(env_items[0]);

/**
 * @brief Get a value from a JSON object by name
 * @param object JSON object
 * @param name Name
 * @return Value or JSON null
 */
static struct json_object_element_s *json_object_get_value_by_name(struct json_object_s *object, const char *name)
{
  for (struct json_object_element_s *element = object->start; element != NULL; element = element->next)
  {
    if (strcmp(element->name->string, name) == 0)
    {
      return element;
    }
  }

  return json_null;
}

/**
 * @brief Handle a message
 * @param pamh PAM handle
 * @param stdout_message Buffer containing the message from stdout
 * @param stdin Stdin stream
 * @return Status
 */
static int handle_message(pam_handle_t *pamh, const char stdout_message[BUFSIZ], FILE *stdin)
{
  // Debug log
  debug("[PAM OAuth Wrapper] Handling message: %s", stdout_message);

  // Parse the buffer
  struct json_value_s *stdout_message_json = json_parse(stdout_message, strlen(stdout_message));

  if (stdout_message_json == NULL)
  {
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to parse JSON: %s\n", stdout_message);
    return PAM_SERVICE_ERR;
  }

  struct json_object_s *stdout_message_object = json_value_as_object(stdout_message_json);

  if (stdout_message_object == NULL)
  {
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to parse JSON object: %s\n", stdout_message);
    return PAM_SERVICE_ERR;
  }

  // Get the message type
  struct json_object_element_s *stdout_message_type_element = json_object_get_value_by_name(stdout_message_object, "type");

  if (stdout_message_type_element == json_null)
  {
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to get message type: %s\n", stdout_message);
    return PAM_SERVICE_ERR;
  }

  struct json_string_s *stdout_message_type = json_value_as_string(stdout_message_type_element->value);

  if (stdout_message_type == json_null)
  {
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to parse message type: %s\n", stdout_message);
    return PAM_SERVICE_ERR;
  }

  // Debug log
  debug("[PAM OAuth Wrapper] Message type: %s\n", stdout_message_type->string);

  // Prompt the user
  if (strcmp(stdout_message_type->string, "prompt") == 0)
  {
    // Get the prompt style
    struct json_object_element_s *stdout_message_style_element = json_object_get_value_by_name(stdout_message_object, "style");

    if (stdout_message_style_element == json_null)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to get prompt style: %s\n", stdout_message);
      return PAM_SERVICE_ERR;
    }

    struct json_number_s *raw_stdout_message_style = json_value_as_number(stdout_message_style_element->value);

    if (raw_stdout_message_style == json_null)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to parse prompt style: %s\n", stdout_message);
      return PAM_SERVICE_ERR;
    }

    int stdout_message_style = atoi(raw_stdout_message_style->number);

    // Get the prompt message
    struct json_object_element_s *stdout_message_message_element = json_object_get_value_by_name(stdout_message_object, "message");

    if (stdout_message_message_element == json_null)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to get prompt message: %s\n", stdout_message);
      return PAM_SERVICE_ERR;
    }

    struct json_string_s *stdout_message_message = json_value_as_string(stdout_message_message_element->value);

    if (stdout_message_message == json_null)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to parse prompt message: %s\n", stdout_message);
      return PAM_SERVICE_ERR;
    }

    // Prompt with data
    char *response = NULL;
    int result = pam_prompt(pamh, stdout_message_style, &response, "%s", stdout_message_message->string);

    if (result != PAM_SUCCESS)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to prompt user input: %s\n", pam_strerror(pamh, result));
      return PAM_SERVICE_ERR;
    }

    // Debug log
    debug("[PAM OAuth Wrapper] User response: %s\n", response);

    // Forward stdin
    if (response != NULL)
    {
      // Write to stdin
      if (fprintf(stdin, "%s\n", response) < 0)
      {
        fprintf(stderr, "[PAM OAuth Wrapper] Failed to forward stdin: %s\n", strerror(errno));
        return PAM_SERVICE_ERR;
      }

      // Flush stdin
      if (fflush(stdin) == EOF)
      {
        fprintf(stderr, "[PAM OAuth Wrapper] Failed to flush stdin: %s\n", strerror(errno));
        // Don't return here because the program may have already terminated
      }

      free(response);
    }
  }
  // Put environment variables
  else if (strcmp(stdout_message_type->string, "putenv") == 0)
  {
    // Get the variable name
    struct json_object_element_s *stdout_message_name_element = json_object_get_value_by_name(stdout_message_object, "name");

    if (stdout_message_name_element == json_null)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to get environment variable name: %s\n", stdout_message);
      return PAM_SERVICE_ERR;
    }

    struct json_string_s *stdout_message_name = json_value_as_string(stdout_message_name_element->value);

    if (stdout_message_name == json_null)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to parse environment variable name: %s\n", stdout_message);
      return PAM_SERVICE_ERR;
    }

    // Get the variable value
    struct json_object_element_s *stdout_message_value_element = json_object_get_value_by_name(stdout_message_object, "value");

    if (stdout_message_value_element == json_null)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to get environment variable value: %s\n", stdout_message);
      return PAM_SERVICE_ERR;
    }

    struct json_string_s *stdout_message_value = json_value_as_string(stdout_message_value_element->value);

    if (stdout_message_value == json_null)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to parse environment variable value: %s\n", stdout_message);
      return PAM_SERVICE_ERR;
    }

    // Debug log
    debug("[PAM OAuth Wrapper] Putting environment variable: %s=%s\n", stdout_message_name->string, stdout_message_value->string);

    // Put the environment variable
    char *env;
    int result = asprintf(&env, "%s=%s", stdout_message_name->string, stdout_message_value->string);

    if (result < 0)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to set environment variable: %s\n", strerror(errno));
      return PAM_SERVICE_ERR;
    }

    result = pam_putenv(pamh, env);

    if (result != PAM_SUCCESS)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to put environment variable: %s\n", pam_strerror(pamh, result));
      return PAM_SERVICE_ERR;
    }

    free(env);
  }
  // Unknown message type
  else
  {
    fprintf(stderr, "[PAM OAuth Wrapper] Unknown message type: %s\n", stdout_message_type->string);
    return PAM_SERVICE_ERR;
  }

  return PAM_SUCCESS;
}

/**
 * @brief Run a command and stdout
 * @param pamh PAM handle
 * @param type PAM invocation type
 * @param argc Argument count
 * @param argv Arguments
 * @return Status
 */
static int run(pam_handle_t *pamh, const char *type, const int argc, const char **argv)
{
  // Get existing environment variables
  char **envlist = pam_getenvlist(pamh);
  int envlist_length = 0;
  for (envlist_length = 0; envlist[envlist_length] != NULL; ++envlist_length)
  {
  }

  // Reallocate memory for the new environment variables (including PAM_TYPE and NULL terminator)
  envlist = realloc(envlist, (envlist_length + env_items_length + 2) * sizeof(*envlist));
  if (envlist == NULL)
  {
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to reallocate memory: %s\n", strerror(errno));
    return PAM_SERVICE_ERR;
  }

  // Add custom environment variables
  for (int i = 0; i < env_items_length; ++i)
  {
    // Get the item
    const void *item;
    int result = pam_get_item(pamh, env_items[i].item, &item);
    if (result != PAM_SUCCESS)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to get item: %s\n", pam_strerror(pamh, result));
      return PAM_SERVICE_ERR;
    }

    // Set the item to an empty string if it's NULL
    if (item == NULL)
    {
      item = "";
    }

    // Set the environment variable
    if (asprintf(&envlist[envlist_length + i], "%s=%s", env_items[i].name, (const char *)item) < 0)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to set environment variable: %s\n", strerror(errno));
      return PAM_SERVICE_ERR;
    }
  }

  // Add the type
  if (asprintf(&envlist[envlist_length + env_items_length], "PAM_TYPE=%s", type) < 0)
  {
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to set environment variable: %s\n", strerror(errno));
    return PAM_SERVICE_ERR;
  }

  // Add the NULL terminator
  envlist[envlist_length + env_items_length + 1] = NULL;

  // Print env
  for (int i = 0; envlist[i] != NULL; ++i)
  {
    fprintf(stderr, "[PAM OAuth Wrapper] env[%d]: %s\n", i, envlist[i]);
  }

  // Initialize stdio pipes
  int stdin_pipe_fds[2] = {-1, -1};
  if (pipe(stdin_pipe_fds) == -1)
  {
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to create stdin pipe: %s\n", strerror(errno));
    return PAM_SERVICE_ERR;
  }

  int stdout_pipe_fds[2] = {-1, -1};
  if (pipe(stdout_pipe_fds) == -1)
  {
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to create stdout pipe: %s\n", strerror(errno));
    return PAM_SERVICE_ERR;
  }

  // Fork
  pid_t pid = fork();

  switch (pid)
  {
  // Error
  case -1:
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to fork: %s\n", strerror(errno));
    return PAM_SERVICE_ERR;
    break;

  // Child
  case 0:
    // Close unused pipe ends
    close(stdin_pipe_fds[1]);
    close(stdout_pipe_fds[0]);

    // Redirect stdio
    if (dup2(stdin_pipe_fds[0], STDIN_FILENO) == -1)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to redirect stdin: %s\n", strerror(errno));
      return PAM_SERVICE_ERR;
    }

    if (dup2(stdout_pipe_fds[1], STDOUT_FILENO) == -1)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to redirect stdout: %s\n", strerror(errno));
      return PAM_SERVICE_ERR;
    }

    // Execute command
    execve(argv[0], (char *const *)argv, envlist);

    // Error
    fprintf(stderr, "[PAM OAuth Wrapper] Failed to execute command: %s\n", strerror(errno));
    return PAM_SERVICE_ERR;
    break;

  // Parent
  default:
    // Close unused pipe ends
    close(stdin_pipe_fds[0]);
    close(stdout_pipe_fds[1]);

    // Open stdio streams
    FILE *stdin_pipe = fdopen(stdin_pipe_fds[1], "w");
    if (stdin_pipe == NULL)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to open stdin pipe: %s\n", strerror(errno));
      return PAM_SERVICE_ERR;
    }

    FILE *stdout_pipe = fdopen(stdout_pipe_fds[0], "r");
    if (stdout_pipe == NULL)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to open stdout pipe: %s\n", strerror(errno));
      return PAM_SERVICE_ERR;
    }

    // Forward stdin and stdout
    char stdout_buffer[BUFSIZ];
    while (fgets(stdout_buffer, sizeof(stdout_buffer), stdout_pipe) != NULL)
    {
      // Handle the message
      int result = handle_message(pamh, stdout_buffer, stdin_pipe);

      // Check for errors
      if (result != PAM_SUCCESS)
      {
        return result;
      }
    }

    // Wait for the child to terminate
    int status;
    if (waitpid(pid, &status, WUNTRACED) == -1)
    {
      fprintf(stderr, "[PAM OAuth Wrapper] Failed to wait for child: %s\n", strerror(errno));
      return PAM_SERVICE_ERR;
    }

    // Log
    fprintf(stderr, "[PAM OAuth Wrapper] Child terminated with status: %d\n", status);

    // Close stdio streams
    fclose(stdin_pipe);
    fclose(stdout_pipe);

    // Return termination signal
    if (WIFSIGNALED(status))
    {
      // Add 128 (See https://stackoverflow.com/a/39269908)
      return 128 + WTERMSIG(status);
    }

    // Return stop signal
    if (WIFSTOPPED(status))
    {
      // Add 128 (See https://stackoverflow.com/a/39269908)
      return 128 + WSTOPSIG(status);
    }

    // Return exit status
    if (WIFEXITED(status))
    {
      return WEXITSTATUS(status);
    }
    break;
  }

  return PAM_SERVICE_ERR;
}

/**
 * @brief Service function for user authentication
 * @param pamh PAM handle
 * @param flags PAM flags (One or more of `PAM_SILENT` or `PAM_DISALLOW_NULL_AUTHTOK`)
 * @param argc Argument count
 * @param argv Arguments
 * @return Status (One of `PAM_AUTH_ERR`, `PAM_CRED_INSUFFICIENT`, `PAM_AUTHINFO_UNAVAIL`, `PAM_SUCCESS`, `PAM_USER_UNKNOWN`, or `PAM_MAXTRIES`)
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return run(pamh, "pam_sm_authenticate", argc, argv);
}

/**
 * @brief Service function to alter credentials
 * @param pamh PAM handle
 * @param flags PAM flags (One or more of `PAM_SILENT`, `PAM_ESTABLISH_CRED`, `PAM_DELETE_CRED`, `PAM_REINITIALIZE_CRED`, or `PAM_REFRESH_CRED`)
 * @param argc Argument count
 * @param argv Arguments
 * @return Status (One of `PAM_CRED_UNAVAIL`, `PAM_CRED_EXPIRED`, `PAM_CRED_ERR`, `PAM_SUCCESS`, or `PAM_USER_UNKNOWN`)
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return run(pamh, "pam_sm_setcred", argc, argv);
}

/**
 * @brief Service function for account management
 * @param pamh PAM handle
 * @param flags PAM flags (One or more of `PAM_SILENT` or `PAM_DISALLOW_NULL_AUTHTOK`)
 * @param argc Argument count
 * @param argv Arguments
 * @return Status (One of `PAM_ACCT_EXPIRED`, `PAM_AUTH_ERR`, `PAM_NEW_AUTHTOK_REQD`, `PAM_PERM_DENIED`, `PAM_SUCCESS`, or `PAM_USER_UNKNOWN`)
 */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return run(pamh, "pam_sm_acct_mgmt", argc, argv);
}

/**
 * @brief Service function to start session management
 * @param pamh PAM handle
 * @param flags PAM flags (One or more of `PAM_SILENT`)
 * @param argc Argument count
 * @param argv Arguments
 * @return Status (One of `PAM_SESSION_ERR` or `PAM_SUCCESS`)
 */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return run(pamh, "pam_sm_open_session", argc, argv);
}

/**
 * @brief Service function to terminate session management
 * @param pamh PAM handle
 * @param flags PAM flags (One or more of `PAM_SILENT`)
 * @param argc Argument count
 * @param argv Arguments
 * @return Status (One of `PAM_SESSION_ERR` or `PAM_SUCCESS`)
 */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return run(pamh, "pam_sm_close_session", argc, argv);
}

/**
 * @brief Service function to alter authentication token (password)
 * @param pamh PAM handle
 * @param flags PAM flags (One or more of `PAM_SILENT`, `PAM_CHANGE_EXPIRED_AUTHTOK`, `PAM_PRELIM_CHECK`, or `PAM_UPDATE_AUTHTOK`)
 * @param argc Argument count
 * @param argv Arguments
 * @return Status (One of `PAM_AUTHTOK_ERR`, `PAM_AUTHTOK_RECOVERY_ERR`, `PAM_AUTHTOK_LOCK_BUSY`, `PAM_AUTHTOK_DISABLE_AGING`, `PAM_PERM_DENIED`, `PAM_TRY_AGAIN`, `PAM_SUCCESS`, or `PAM_USER_UNKNOWN`)
 */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return run(pamh, "pam_sm_chauthtok", argc, argv);
}
