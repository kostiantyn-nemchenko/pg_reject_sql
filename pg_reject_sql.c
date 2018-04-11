#include "postgres.h"
#include "tcop/utility.h"
#include "miscadmin.h"

#define ALLOWED_USER "postgres"

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

static ProcessUtility_hook_type prev_utility_hook = NULL;

static void
reject_sql(
#if (PG_VERSION_NUM >= 100000)
           PlannedStmt *pstmt,
#else
           Node *parsetree,
#endif  /* PG_VERSION_NUM */
           const char *queryString,
           ProcessUtilityContext context,
           ParamListInfo params,
#if (PG_VERSION_NUM >= 100000)
           QueryEnvironment *queryEnv,
#endif  /* PG_VERSION_NUM */
           DestReceiver *dest,
           char *completionTag)
{
#if (PG_VERSION_NUM >= 100000)
    Node *parsetree = pstmt->utilityStmt;
#endif

    switch (nodeTag(parsetree))
    {
        /* Catch ALTER SYSTEM statement */
        case T_AlterSystemStmt:
        {
            const char *current_user = GetUserNameFromId(GetUserId()
#if (PG_VERSION_NUM >= 90500)
            , false
#endif
                                                        );

            if (strcmp(current_user, ALLOWED_USER) != 0)
            {
                ereport(ERROR,
                        (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                         errmsg("user %s is not permitted to execute ALTER SYSTEM",
                                current_user)));
            }
            break;
        }
        default:
            break;
    }

    if (prev_utility_hook)
    {
        (*prev_utility_hook) (
#if (PG_VERSION_NUM >= 100000)
                              pstmt,
#else
                              parsetree,
#endif  /* PG_VERSION_NUM */
                              queryString,
                              context, params,
#if (PG_VERSION_NUM >= 100000)
                              queryEnv,
#endif  /* PG_VERSION_NUM */
                              dest, completionTag);
    }
    else
    {
        standard_ProcessUtility(
#if (PG_VERSION_NUM >= 100000)
                                pstmt,
#else
                                parsetree,
#endif  /* PG_VERSION_NUM */
                                queryString,
                                context, params,
#if (PG_VERSION_NUM >= 100000)
                                queryEnv,
#endif  /* PG_VERSION_NUM */
                                dest, completionTag);
    }
}

void
_PG_init(void)
{
    prev_utility_hook = ProcessUtility_hook;
    ProcessUtility_hook = reject_sql;
}

void
_PG_fini(void)
{
    ProcessUtility_hook = prev_utility_hook;
}
