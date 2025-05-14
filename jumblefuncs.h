/*-------------------------------------------------------------------------
 *
 * jumblefuncs.h
 *	  Helper functions for calculating a plan ID through a "jumble".
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  contrib/pg_stat_plans/jumblefuncs.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef JUMBLEFUNCS_H
#define JUMBLEFUNCS_H

#include "nodes/parsenodes.h"
#include "nodes/pathnodes.h"
#include "nodes/queryjumble.h"

extern JumbleState *InitJumble(void);
extern void JumbleNode(JumbleState *jstate, Node *node);
extern uint64 HashJumbleState(JumbleState *jstate);

/* Plan jumbling routines */
extern void JumbleRangeTable(JumbleState *jstate, List *rtable);


#endif							/* JUMBLEFUNCS_H */
