#include "tm-modules.h"

TmModule tmm_modules[TMM_SIZE];

TmModule *TmModuleGetByName(const char *name)
{
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (strcmp(t->name, name) == 0)
            return t;
    }

    return NULL;
}

int TmModuleGetIDForTM(TmModule *tm)
{
    TmModule *t;
    int i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (strcmp(t->name, tm->name) == 0)
            return i;
    }

    return -1;
}

void TmModuleRunInit(void)
{
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (t->Init == NULL)
            continue;

        t->Init();
    }
}

void TmModuleRunDeInit(void)
{
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (t->DeInit == NULL)
            continue;

        t->DeInit();
    }
}