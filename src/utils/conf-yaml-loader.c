#include <yaml.h>
#include <linux/limits.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "conf-yaml-loader.h"
#include "utils/conf.h"
#include "utils/util-error.h"
#include "utils/util-debug.h"
#include "utils/util-path.h"
#include "base.h"

#define YAML_VERSION_MAJOR 1
#define YAML_VERSION_MINOR 1

/* The maximum level of recursion allowed while parsing the YAML
 * file. */
#define RECURSION_LIMIT 128

/* Sometimes we'll have to create a node name on the fly (integer
 * conversion, etc), so this is a default length to allocate that will
 * work most of the time. */
#define DEFAULT_NAME_LEN 16

#define MANGLE_ERRORS_MAX 10
static int mangle_errors = 0;

static char *conf_dirname = NULL;

static int ConfYamlParse(yaml_parser_t *parser, ConfNode *parent, int inseq, int rlevel);

/* Configuration processing states. */
enum conf_state {
    CONF_KEY = 0,
    CONF_VAL,
    CONF_INCLUDE,
};

/**
 * \brief Mangle unsupported characters.
 *
 * \param string A pointer to an null terminated string.
 *
 * \retval none
 */
static void
Mangle(char *string)
{
    char *c;

    while ((c = strchr(string, '_')))
        *c = '-';

    return;
}

/**
 * \brief Set the directory name of the configuration file.
 *
 * \param filename The configuration filename.
 */
static void
ConfYamlSetConfDirname(const char *filename)
{
    char *ep;

    ep = strrchr(filename, '\\');
    if (ep == NULL)
        ep = strrchr(filename, '/');

    if (ep == NULL) {
        conf_dirname = strdup(".");
        if (conf_dirname == NULL) {
            FatalError(SC_ERR_FATAL,
                       "ERROR: Failed to allocate memory while loading configuration.");
        }
    }
    else {
        conf_dirname = strdup(filename);
        if (conf_dirname == NULL) {
            FatalError(SC_ERR_FATAL,
                       "ERROR: Failed to allocate memory while loading configuration.");
        }
        conf_dirname[ep - filename] = '\0';
    }
}

/**
 * \brief Include a file in the configuration.
 *
 * \param parent The configuration node the included configuration will be
 *          placed at.
 * \param filename The filename to include.
 *
 * \retval 0 on success, -1 on failure.
 */
static int
ConfYamlHandleInclude(ConfNode *parent, const char *filename)
{
    yaml_parser_t parser;
    char include_filename[PATH_MAX];
    FILE *file = NULL;
    int ret = -1;

    if (yaml_parser_initialize(&parser) != 1) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Failed to initialize YAML parser");
        return -1;
    }

    if (PathIsAbsolute(filename)) {
        strlcpy(include_filename, filename, sizeof(include_filename));
    }
    else {
        snprintf(include_filename, sizeof(include_filename), "%s/%s",
                 conf_dirname, filename);
    }

    file = fopen(include_filename, "r");
    if (file == NULL) {
        SCLogError(SC_ERR_FOPEN,
                   "Failed to open configuration include file %s: %s",
                   include_filename, strerror(errno));
        goto done;
    }

    yaml_parser_set_input_file(&parser, file);

    if (ConfYamlParse(&parser, parent, 0, 0) != 0) {
        SCLogError(SC_ERR_CONF_YAML_ERROR,
                   "Failed to include configuration file %s", filename);
        goto done;
    }

    ret = 0;

    done:
    yaml_parser_delete(&parser);
    if (file != NULL) {
        fclose(file);
    }

    return ret;
}

/**
 * \brief Parse a YAML layer.
 *
 * \param parser A pointer to an active yaml_parser_t.
 * \param parent The parent configuration node.
 *
 * \retval 0 on success, -1 on failure.
 */
static int
ConfYamlParse(yaml_parser_t *parser, ConfNode *parent, int inseq, int rlevel)
{
    ConfNode *node = parent;
    yaml_event_t event;
    memset(&event, 0, sizeof(event));
    int done = 0;
    int state = 0;
    int seq_idx = 0;
    int retval = 0;
    int was_empty = -1;

    if (rlevel++ > RECURSION_LIMIT) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Recursion limit reached while parsing "
                                           "configuration file, aborting.");
        return -1;
    }

    while (!done) {
        if (!yaml_parser_parse(parser, &event)) {
            SCLogError(SC_ERR_CONF_YAML_ERROR,
                       "Failed to parse configuration file at line %" PRIuMAX ": %s\n",
                    (uintmax_t)parser->problem_mark.line, parser->problem);
            retval = -1;
            break;
        }

        if (event.type == YAML_DOCUMENT_START_EVENT) {
            SCLogDebug("event.type=YAML_DOCUMENT_START_EVENT; state=%d", state);
            /* Verify YAML version - its more likely to be a valid
             * Suricata configuration file if the version is
             * correct. */
            yaml_version_directive_t *ver =
                    event.data.document_start.version_directive;
            if (ver == NULL) {
                SCLogError(SC_ERR_CONF_YAML_ERROR, "ERROR: Invalid configuration file.");
                SCLogError(SC_ERR_CONF_YAML_ERROR,
                           "The configuration file must begin with the following two lines: %%YAML 1.1 and ---");
                goto fail;
            }
            int major = ver->major;
            int minor = ver->minor;
            if (!(major == YAML_VERSION_MAJOR && minor == YAML_VERSION_MINOR)) {
                SCLogError(SC_ERR_CONF_YAML_ERROR, "ERROR: Invalid YAML version.  Must be 1.1");
                goto fail;
            }
        }
        else if (event.type == YAML_SCALAR_EVENT) {
            char *value = (char *)event.data.scalar.value;
            char *tag = (char *)event.data.scalar.tag;
            SCLogDebug("event.type=YAML_SCALAR_EVENT; state=%d; value=%s; "
                       "tag=%s; inseq=%d", state, value, tag, inseq);

            /* Skip over empty scalar values while in KEY state. This
             * tends to only happen on an empty file, where a scalar
             * event probably shouldn't fire anyways. */
            if (state == CONF_KEY && strlen(value) == 0) {
                goto next;
            }

            if (inseq) {
                char sequence_node_name[DEFAULT_NAME_LEN];
                snprintf(sequence_node_name, DEFAULT_NAME_LEN, "%d", seq_idx++);
                ConfNode *seq_node = NULL;
                if (was_empty < 0) {
                    // initialize was_empty
                    if (TAILQ_EMPTY(&parent->head)) {
                        was_empty = 1;
                    } else {
                        was_empty = 0;
                    }
                }
                // we only check if the node's list was not empty at first
                if (was_empty == 0) {
                    seq_node = ConfNodeLookupChild(parent, sequence_node_name);
                }
                if (seq_node != NULL) {
                    /* The sequence node has already been set, probably
                     * from the command line.  Remove it so it gets
                     * re-added in the expected order for iteration.
                     */
                    TAILQ_REMOVE(&parent->head, seq_node, next);
                }
                else {
                    seq_node = ConfNodeNew();
                    if (unlikely(seq_node == NULL)) {
                        goto fail;
                    }
                    seq_node->name = strdup(sequence_node_name);
                    if (unlikely(seq_node->name == NULL)) {
                        free(seq_node);
                        goto fail;
                    }
                    seq_node->val = strdup(value);
                    if (unlikely(seq_node->val == NULL)) {
                        free(seq_node->name);
                        goto fail;
                    }
                }
                TAILQ_INSERT_TAIL(&parent->head, seq_node, next);
            }
            else {
                if (state == CONF_INCLUDE) {
                    SCLogInfo("Including configuration file %s.", value);
                    if (ConfYamlHandleInclude(parent, value) != 0) {
                        goto fail;
                    }
                    state = CONF_KEY;
                }
                else if (state == CONF_KEY) {

                    if (strcmp(value, "include") == 0) {
                        state = CONF_INCLUDE;
                        goto next;
                    }

                    if (parent->is_seq) {
                        if (parent->val == NULL) {
                            parent->val = strdup(value);
                            if (parent->val && strchr(parent->val, '_'))
                                Mangle(parent->val);
                        }
                    }
                    ConfNode *existing = ConfNodeLookupChild(parent, value);
                    if (existing != NULL) {
                        if (!existing->final) {
                            SCLogInfo("Configuration node '%s' redefined.",
                                      existing->name);
                            ConfNodePrune(existing);
                        }
                        node = existing;
                    }
                    else {
                        node = ConfNodeNew();
                        node->name = strdup(value);
                        if (node->name && strchr(node->name, '_')) {
                            if (!(parent->name &&
                                  ((strcmp(parent->name, "address-groups") == 0) ||
                                   (strcmp(parent->name, "port-groups") == 0)))) {
                                Mangle(node->name);
                                if (mangle_errors < MANGLE_ERRORS_MAX) {
                                    SCLogWarning(SC_WARN_DEPRECATED,
                                                 "%s is deprecated. Please use %s on line %"PRIuMAX".",
                                            value, node->name, (uintmax_t)parser->mark.line+1);
                                    mangle_errors++;
                                    if (mangle_errors >= MANGLE_ERRORS_MAX)
                                        SCLogWarning(SC_WARN_DEPRECATED, "not showing more "
                                                                         "parameter name warnings.");
                                }
                            }
                        }
                        TAILQ_INSERT_TAIL(&parent->head, node, next);
                    }
                    state = CONF_VAL;
                }
                else {
                    if ((tag != NULL) && (strcmp(tag, "!include") == 0)) {
                        SCLogInfo("Including configuration file %s at "
                                  "parent node %s.", value, node->name);
                        if (ConfYamlHandleInclude(node, value) != 0)
                            goto fail;
                    }
                    else if (!node->final) {
                        if (node->val != NULL)
                            free(node->val);
                        node->val = strdup(value);
                    }
                    state = CONF_KEY;
                }
            }
        }
        else if (event.type == YAML_SEQUENCE_START_EVENT) {
            SCLogDebug("event.type=YAML_SEQUENCE_START_EVENT; state=%d", state);
            if (ConfYamlParse(parser, node, 1, rlevel) != 0)
                goto fail;
            node->is_seq = 1;
            state = CONF_KEY;
        }
        else if (event.type == YAML_SEQUENCE_END_EVENT) {
            SCLogDebug("event.type=YAML_SEQUENCE_END_EVENT; state=%d", state);
            done = 1;
        }
        else if (event.type == YAML_MAPPING_START_EVENT) {
            SCLogDebug("event.type=YAML_MAPPING_START_EVENT; state=%d", state);
            if (inseq) {
                char sequence_node_name[DEFAULT_NAME_LEN];
                snprintf(sequence_node_name, DEFAULT_NAME_LEN, "%d", seq_idx++);
                ConfNode *seq_node = ConfNodeLookupChild(node,
                                                         sequence_node_name);
                if (seq_node != NULL) {
                    /* The sequence node has already been set, probably
                     * from the command line.  Remove it so it gets
                     * re-added in the expected order for iteration.
                     */
                    TAILQ_REMOVE(&node->head, seq_node, next);
                }
                else {
                    seq_node = ConfNodeNew();
                    if (unlikely(seq_node == NULL)) {
                        goto fail;
                    }
                    seq_node->name = strdup(sequence_node_name);
                    if (unlikely(seq_node->name == NULL)) {
                        free(seq_node);
                        goto fail;
                    }
                }
                seq_node->is_seq = 1;
                TAILQ_INSERT_TAIL(&node->head, seq_node, next);
                if (ConfYamlParse(parser, seq_node, 0, rlevel) != 0)
                    goto fail;
            }
            else {
                if (ConfYamlParse(parser, node, inseq, rlevel) != 0)
                    goto fail;
            }
            state = CONF_KEY;
        }
        else if (event.type == YAML_MAPPING_END_EVENT) {
            SCLogDebug("event.type=YAML_MAPPING_END_EVENT; state=%d", state);
            done = 1;
        }
        else if (event.type == YAML_STREAM_END_EVENT) {
            SCLogDebug("event.type=YAML_STREAM_END_EVENT; state=%d", state);
            done = 1;
        }

        next:
        yaml_event_delete(&event);
        continue;

        fail:
        yaml_event_delete(&event);
        retval = -1;
        break;
    }

    rlevel--;
    return retval;
}

/**
 * \brief Load configuration from a YAML file.
 *
 * This function will load a configuration file.  On failure -1 will
 * be returned and it is suggested that the program then exit.  Any
 * errors while loading the configuration file will have already been
 * logged.
 *
 * \param filename Filename of configuration file to load.
 *
 * \retval 0 on success, -1 on failure.
 */
int
ConfYamlLoadFile(const char *filename)
{
    FILE *infile;
    yaml_parser_t parser;
    int ret;
    ConfNode *root = ConfGetRootNode();

    if (yaml_parser_initialize(&parser) != 1) {
        SCLogError(SC_ERR_FATAL, "failed to initialize yaml parser.");
        return -1;
    }

    struct stat stat_buf;
    if (stat(filename, &stat_buf) == 0) {
        if (stat_buf.st_mode & S_IFDIR) {
            SCLogError(SC_ERR_FATAL, "yaml argument is not a file but a directory: %s. "
                                     "Please specify the yaml file in your -c option.", filename);
            yaml_parser_delete(&parser);
            return -1;
        }
    }

    // coverity[toctou : FALSE]
    infile = fopen(filename, "r");
    if (infile == NULL) {
        SCLogError(SC_ERR_FATAL, "failed to open file: %s: %s", filename,
                   strerror(errno));
        yaml_parser_delete(&parser);
        return -1;
    }

    if (conf_dirname == NULL) {
        ConfYamlSetConfDirname(filename);
    }

    yaml_parser_set_input_file(&parser, infile);
    ret = ConfYamlParse(&parser, root, 0, 0);
    yaml_parser_delete(&parser);
    fclose(infile);

    return ret;
}

/**
 * \brief Load configuration from a YAML string.
 */
int
ConfYamlLoadString(const char *string, size_t len)
{
    ConfNode *root = ConfGetRootNode();
    yaml_parser_t parser;
    int ret;

    if (yaml_parser_initialize(&parser) != 1) {
        fprintf(stderr, "Failed to initialize yaml parser.\n");
        exit(EXIT_FAILURE);
    }
    yaml_parser_set_input_string(&parser, (const unsigned char *)string, len);
    ret = ConfYamlParse(&parser, root, 0, 0);
    yaml_parser_delete(&parser);

    return ret;
}

/**
 * \brief Load configuration from a YAML file, insert in tree at 'prefix'
 *
 * This function will load a configuration file and insert it into the
 * config tree at 'prefix'. This means that if this is called with prefix
 * "abc" and the file contains a parameter "def", it will be loaded as
 * "abc.def".
 *
 * \param filename Filename of configuration file to load.
 * \param prefix Name prefix to use.
 *
 * \retval 0 on success, -1 on failure.
 */
int
ConfYamlLoadFileWithPrefix(const char *filename, const char *prefix)
{
    FILE *infile;
    yaml_parser_t parser;
    int ret;
    ConfNode *root = ConfGetNode(prefix);

    if (yaml_parser_initialize(&parser) != 1) {
        SCLogError(SC_ERR_FATAL, "failed to initialize yaml parser.");
        return -1;
    }

    struct stat stat_buf;
    /* coverity[toctou] */
    if (stat(filename, &stat_buf) == 0) {
        if (stat_buf.st_mode & S_IFDIR) {
            SCLogError(SC_ERR_FATAL, "yaml argument is not a file but a directory: %s. "
                                     "Please specify the yaml file in your -c option.", filename);
            return -1;
        }
    }

    /* coverity[toctou] */
    infile = fopen(filename, "r");
    if (infile == NULL) {
        SCLogError(SC_ERR_FATAL, "failed to open file: %s: %s", filename,
                   strerror(errno));
        yaml_parser_delete(&parser);
        return -1;
    }

    if (conf_dirname == NULL) {
        ConfYamlSetConfDirname(filename);
    }

    if (root == NULL) {
        /* if node at 'prefix' doesn't yet exist, add a place holder */
        ConfSet(prefix, "<prefix root node>");
        root = ConfGetNode(prefix);
        if (root == NULL) {
            fclose(infile);
            yaml_parser_delete(&parser);
            return -1;
        }
    }
    yaml_parser_set_input_file(&parser, infile);
    ret = ConfYamlParse(&parser, root, 0, 0);
    yaml_parser_delete(&parser);
    fclose(infile);

    return ret;
}


