#include "conf.h"
#include "utils/util-debug.h"
#include "base.h"
#include "util-mem.h"
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

/** Maximum size of a complete domain name. */
#define NODE_NAME_MAX 1024

static ConfNode *root = NULL;

size_t strlcpy(char *dst, const char *src, size_t siz)
{
  register char *d = dst;
  register const char *s = src;
  register size_t n = siz;

  /* Copy as many bytes as will fit */
  if (n != 0 && --n != 0) {
    do {
      if ((*d++ = *s++) == 0)
        break;
    } while (--n != 0);
  }

  /* Not enough room in dst, add NUL and traverse rest of src */
  if (n == 0) {
    if (siz != 0)
      *d = '\0'; /* NUL-terminate dst */
    while (*s++)
      ;
  }

  return(s - src - 1); /* count does not include NUL */
}

ConfNode *ConfGetRootNode(void)
{
    return root;
}

static ConfNode *ConfGetNodeOrCreate(const char *name, int final)
{
    ConfNode *parent = root;
    ConfNode *node = NULL;
    char node_name[NODE_NAME_MAX];
    char *key;
    char *next;

    if (strlcpy(node_name, name, sizeof(node_name)) >= sizeof(node_name)) {
        SCLogError(SC_ERR_CONF_NAME_TOO_LONG,
                   "Configuration name too long: %s", name);
        return NULL;
    }

    key = node_name;

    do {
        if ((next = strchr(key, '.')) != NULL)
            *next++ = '\0';
        if ((node = ConfNodeLookupChild(parent, key)) == NULL) {
            node = ConfNodeNew();
            if (unlikely(node == NULL)) {
                SCLogWarning(SC_ERR_MEM_ALLOC,
                             "Failed to allocate memory for configuration.");
                goto end;
            }
            node->name = SCStrdup(key);
            if (unlikely(node->name == NULL)) {
                ConfNodeFree(node);
                node = NULL;
                SCLogWarning(SC_ERR_MEM_ALLOC,
                             "Failed to allocate memory for configuration.");
                goto end;
            }
            node->parent = parent;
            node->final = final;
            TAILQ_INSERT_TAIL(&parent->head, node, next);
        }
        key = next;
        parent = node;
    } while (next != NULL);

    end:
    return node;
}

int ConfSet(const char *name, const char *val)
{
    ConfNode *node = ConfGetNodeOrCreate(name, 0);
    if (node == NULL || node->final) {
        return 0;
    }
    if (node->val != NULL)
        SCFree(node->val);
    node->val = SCStrdup(val);
    if (unlikely(node->val == NULL)) {
        return 0;
    }
    return 1;
}

int ConfGetChildValue(const ConfNode *base, const char *name, const char **vptr)
{
    ConfNode *node = ConfNodeLookupChild(base, name);

    if (node == NULL) {
        SCLogDebug("failed to lookup configuration parameter '%s'", name);
        return 0;
    }
    else {
        *vptr = node->val;
        return 1;
    }
}

int ConfGetChildValueWithDefault(const ConfNode *base, const ConfNode *dflt,
                                 const char *name, const char **vptr)
{
    int ret = ConfGetChildValue(base, name, vptr);
    /* Get 'default' value */
    if (ret == 0 && dflt) {
        return ConfGetChildValue(dflt, name, vptr);
    }
    return ret;
}

int ConfValIsTrue(const char *val)
{
    const char *trues[] = {"1", "yes", "true", "on"};
    size_t u;

    for (u = 0; u < sizeof(trues) / sizeof(trues[0]); u++) {
        if (strcasecmp(val, trues[u]) == 0) {
            return 1;
        }
    }

    return 0;
}

void ConfInit(void)
{
    if (root != NULL) {
        SCLogDebug("already initialized");
        return;
    }
    root = ConfNodeNew();
    if (root == NULL) {
        FatalError(SC_ERR_FATAL,
                   "ERROR: Failed to allocate memory for root configuration node, "
                   "aborting.");
    }
    SCLogDebug("configuration module initialized");
}

int ConfValIsFalse(const char *val)
{
    const char *falses[] = {"0", "no", "false", "off"};
    size_t u;

    for (u = 0; u < sizeof(falses) / sizeof(falses[0]); u++) {
        if (strcasecmp(val, falses[u]) == 0) {
            return 1;
        }
    }

    return 0;
}

int ConfGetChildValueBool(const ConfNode *base, const char *name, int *val)
{
    const char *strval = NULL;

    *val = 0;
    if (ConfGetChildValue(base, name, &strval) == 0)
        return 0;

    *val = ConfValIsTrue(strval);

    return 1;
}


int ConfGetChildValueInt(const ConfNode *base, const char *name, intmax_t *val)
{
    const char *strval = NULL;
    intmax_t tmpint;
    char *endptr;

    if (ConfGetChildValue(base, name, &strval) == 0)
        return 0;
    errno = 0;
    tmpint = strtoimax(strval, &endptr, 0);
    if (strval[0] == '\0' || *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "malformed integer value "
                                                   "for %s with base %s: '%s'", name, base->name, strval);
        return 0;
    }
    if (errno == ERANGE && (tmpint == INTMAX_MAX || tmpint == INTMAX_MIN)) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "integer value for %s with "
                                                   " base %s out of range: '%s'", name, base->name, strval);
        return 0;
    }

    *val = tmpint;
    return 1;

}

int ConfGetChildValueIntWithDefault(const ConfNode *base, const ConfNode *dflt,
                                    const char *name, intmax_t *val)
{
    int ret = ConfGetChildValueInt(base, name, val);
    /* Get 'default' value */
    if (ret == 0 && dflt) {
        return ConfGetChildValueInt(dflt, name, val);
    }
    return ret;
}

int ConfGetChildValueBoolWithDefault(const ConfNode *base, const ConfNode *dflt,
                                     const char *name, int *val)
{
    int ret = ConfGetChildValueBool(base, name, val);
    /* Get 'default' value */
    if (ret == 0 && dflt) {
        return ConfGetChildValueBool(dflt, name, val);
    }
    return ret;
}

ConfNode *ConfNodeNew(void)
{
    ConfNode *new;

    new = calloc(1, sizeof(*new));
    if (unlikely(new == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&new->head);

    return new;
}

void ConfNodeFree(ConfNode *node)
{
    ConfNode *tmp;

    while ((tmp = TAILQ_FIRST(&node->head))) {
        TAILQ_REMOVE(&node->head, tmp, next);
        ConfNodeFree(tmp);
    }

    if (node->name != NULL)
        SCFree(node->name);
    if (node->val != NULL)
        SCFree(node->val);
    SCFree(node);
}

int ConfSetFinal(const char *name, const char *val)
{
  ConfNode *node = ConfGetNodeOrCreate(name, 1);
  if (node == NULL) {
    return 0;
  }
  if (node->val != NULL)
    SCFree(node->val);
  node->val = SCStrdup(val);
  if (unlikely(node->val == NULL)) {
    return 0;
  }
  node->final = 1;
  return 1;
}

ConfNode *ConfGetNode(const char *name)
{
  ConfNode *node = root;
  char node_name[NODE_NAME_MAX];
  char *key;
  char *next;

  if (strlcpy(node_name, name, sizeof(node_name)) >= sizeof(node_name)) {
    SCLogError(SC_ERR_CONF_NAME_TOO_LONG,
               "Configuration name too long: %s", name);
    return NULL;
  }

  key = node_name;
  do {
    if ((next = strchr(key, '.')) != NULL)
      *next++ = '\0';
    node = ConfNodeLookupChild(node, key);
    key = next;
  } while (next != NULL && node != NULL);

  return node;
}

int ConfGet(const char *name, const char **vptr)
{
    ConfNode *node = ConfGetNode(name);
    if (node == NULL) {
        SCLogDebug("failed to lookup configuration parameter '%s'", name);
        return 0;
    }
    else {
        *vptr = node->val;
        return 1;
    }
}

int ConfGetValue(const char *name, const char **vptr)
{
  ConfNode *node;

  if (name == NULL) {
    SCLogError(SC_ERR_INVALID_ARGUMENT,"parameter 'name' is NULL");
    return -2;
  }

  node = ConfGetNode(name);

  if (node == NULL) {
    SCLogDebug("failed to lookup configuration parameter '%s'", name);
    return 0;
  }
  else {

    if (node->val == NULL) {
      SCLogDebug("value for configuration parameter '%s' is NULL", name);
      return -1;
    }

    *vptr = node->val;
    return 1;
  }

}

int ConfGetInt(const char *name, intmax_t *val)
{
  const char *strval = NULL;
  intmax_t tmpint;
  char *endptr;

  if (ConfGet(name, &strval) == 0)
    return 0;

  if (strval == NULL) {
    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "malformed integer value "
                                               "for %s: NULL", name);
    return 0;
  }

  errno = 0;
  tmpint = strtoimax(strval, &endptr, 0);
  if (strval[0] == '\0' || *endptr != '\0') {
    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "malformed integer value "
                                               "for %s: '%s'", name, strval);
    return 0;
  }
  if (errno == ERANGE && (tmpint == INTMAX_MAX || tmpint == INTMAX_MIN)) {
    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "integer value for %s out "
                                               "of range: '%s'", name, strval);
    return 0;
  }

  *val = tmpint;
  return 1;
}

int ConfGetBool(const char *name, int *val)
{
  const char *strval = NULL;

  *val = 0;
  if (ConfGetValue(name, &strval) != 1)
    return 0;

  *val = ConfValIsTrue(strval);

  return 1;
}

ConfNode *ConfNodeLookupChild(const ConfNode *node, const char *name)
{
  ConfNode *child;

  if (node == NULL || name == NULL) {
    return NULL;
  }

  TAILQ_FOREACH(child, &node->head, next) {
    if (child->name != NULL && strcmp(child->name, name) == 0)
      return child;
  }

  return NULL;
}

const char *ConfNodeLookupChildValue(const ConfNode *node, const char *name)
{
  ConfNode *child;

  child = ConfNodeLookupChild(node, name);
  if (child != NULL)
    return child->val;

  return NULL;
}

void ConfNodePrune(ConfNode *node)
{
    ConfNode *item, *it;

    for (item = TAILQ_FIRST(&node->head); item != NULL; item = it) {
        it = TAILQ_NEXT(item, next);
        if (!item->final) {
            ConfNodePrune(item);
            if (TAILQ_EMPTY(&item->head)) {
                TAILQ_REMOVE(&node->head, item, next);
                if (item->name != NULL)
                    SCFree(item->name);
                if (item->val != NULL)
                    SCFree(item->val);
                SCFree(item);
            }
        }
    }

    if (node->val != NULL) {
        SCFree(node->val);
        node->val = NULL;
    }
}