#include "postgres.h"
#include "tcop/utility.h"
#include "miscadmin.h"

#define ALLOWED_USER "postgres"

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

static ProcessUtility_hook_type prev_utility_hook = NULL;

static void
reject_sql(PlannedStmt *pstmt,
		   const char *queryString,
		   ProcessUtilityContext context,
		   ParamListInfo params,
           QueryEnvironment *queryEnv,
		   DestReceiver *dest,
		   char *completionTag)
{
    Node *parsetree = pstmt->utilityStmt;

	switch (nodeTag(parsetree))
	{
        /* Catch ALTER SYSTEM statement */
		case T_AlterSystemStmt:
		{
            const char *current_user = GetUserNameFromId(GetUserId(), false);

            if (strcmp(current_user, ALLOWED_USER) != 0)
            {
                ereport(ERROR,
			            (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			             errmsg("user %s is not permitted to execute ALTER SYSTEM",
                                current_user)));
            }
            return;
        }
        default:
            break;
    }

	if (prev_utility_hook)
    {
		(*prev_utility_hook) (pstmt, queryString,
                              context, params, queryEnv,
                              dest, completionTag);
    }
	else
	{
    	standard_ProcessUtility(pstmt, queryString,
                                context, params, queryEnv,
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