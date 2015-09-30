/*
**   VNC Password Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2009 Joe Mondloch
**    JoMo-Kun / jmk@foofus.net
**
**    This program is free software; you can redistribute it and/or modify
**    it under the terms of the GNU General Public License version 2,
**    as published by the Free Software Foundation
**
**    This program is distributed in the hope that it will be useful,
**    but WITHOUT ANY WARRANTY; without even the implied warranty of
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**    GNU General Public License for more details.
**
**    http://www.gnu.org/licenses/gpl.txt
**
**    This program is released under the GPL with the additional exemption
**    that compiling, linking, and/or using OpenSSL is allowed.
**
**   ------------------------------------------------------------------------
**
**   Based on code from: VNCrack [FX/Phenolite]
**
**   RealVNC (VNC Server 4 -- FREE)
**   UltraVNC 1.0.1
**     -No support for MS Logon
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"
#include "d3des.h"

#define MODULE_NAME    "vnc.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for VNC sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: vnc.c 1225 2009-10-13 18:55:27Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"

#define PORT_VNC 5900
#define CHALLENGE_SIZE 16

#define SESSION_SUCCESS 1
#define SESSION_FAILURE 2
#define SESSION_SUCCESS_NO_AUTH 3
#define SESSION_MAX_AUTH_REALVNC 4
#define SESSION_MAX_AUTH_ULTRAVNC 5

typedef struct __VNC_DATA {
  int nMaxAuthSleep; 
} _VNC_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int tryLogin(int hSocket, sLogin** login, _VNC_DATA* _psSessionData, unsigned char* pzChallenge, char* szPassword);
int initModule(sLogin* login, _VNC_DATA *_psSessionData);
int vncSessionSetup(int hSocket, unsigned char* pzChallenge);

// Tell medusa how many parameters this module allows
int getParamNumber()
{
  return 0;    // we don't need no stinking parameters
}

// Displays information about the module and how it must be used
void summaryUsage(char **ppszSummary)
{
  // Memory for ppszSummary will be allocated here - caller is responsible for freeing it
  int  iLength = 0;

  if (*ppszSummary == NULL)
  {
    iLength = strlen(MODULE_SUMMARY_USAGE) + strlen(MODULE_VERSION) + strlen(MODULE_SUMMARY_FORMAT) + 1;
    *ppszSummary = (char*)malloc(iLength);
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT, MODULE_SUMMARY_USAGE, MODULE_VERSION);
  } 
  else 
  {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}

/* Display module usage information */
void showUsage()
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "Available module options:");
  writeVerbose(VB_NONE, "  MAXSLEEP:?");
  writeVerbose(VB_NONE, "    Sets the maximum allowed sleep time when the VNC RealVNC anti-brute force delay");
  writeVerbose(VB_NONE, "    is encountered. This value is in seconds and, if left unset, defaults to 60.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Some versions of VNC have built-in anti-brute force functionality. RealVNC, for example,");
  writeVerbose(VB_NONE, "allows 5 failed attempts and then enforces a 10 second delay. For each subsequent");
  writeVerbose(VB_NONE, "attempt that delay is doubled. UltraVNC appears to allow 6 invalid attempts and then forces");
  writeVerbose(VB_NONE, "a 10 second delay between each following attempt. This module attempts to identify these");
  writeVerbose(VB_NONE, "situations and react appropriately by invoking sleep(). The user can set a sleep limit when");
  writeVerbose(VB_NONE, "brute forcing RealVNC using the MAXSLEEP parameter. Once this value has been reached, the");
  writeVerbose(VB_NONE, "module will exit.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "It should be noted that this module currently supports password-less and password-only VNC");
  writeVerbose(VB_NONE, "servers. If a server is encountered which requires both username/password, the module will");
  writeVerbose(VB_NONE, "report this and exit. Since medusa requires a username to be specified, provide any arbitrary");
  writeVerbose(VB_NONE, "value.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage example: \"-M vnc -m MAXSLEEP:120\"");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _VNC_DATA *psSessionData;
  psSessionData = malloc(sizeof(_VNC_DATA));
  memset(psSessionData, 0, sizeof(_VNC_DATA));
  psSessionData->nMaxAuthSleep = 60;

  if ( !(0 <= argc <= 3) )
  {
    // Show usage information
    writeError(ERR_ERROR, "%s is expecting 0 parameters, but it was passed %d", MODULE_NAME, argc);
  } 
  else 
  {
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);
 
    for (i=0; i<argc; i++) {
      pOptTmp = malloc( strlen(argv[i]) + 1);
      memset(pOptTmp, 0, strlen(argv[i]) + 1);
      strncpy(pOptTmp, argv[i], strlen(argv[i]));
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "MAXSLEEP") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
          psSessionData->nMaxAuthSleep = atoi(pOpt);        
        else
          writeError(ERR_WARNING, "Method MAXSLEEP requires value to be set.");
      }
      else
         writeError(ERR_WARNING, "Invalid method: %s.", pOpt);

      free(pOptTmp);
    }

    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(sLogin* psLogin, _VNC_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  int iRet;
  unsigned char zChallenge[16];
  sConnectParams params;
  int nAngrySleep = 10;
  int bAuthAllowed = FALSE;
  sCredentialSet *psCredSet = NULL;

  psCredSet = malloc( sizeof(sCredentialSet) );
  memset(psCredSet, 0, sizeof(sCredentialSet));

  if (getNextCredSet(psLogin, psCredSet) == FAILURE)
  {
    writeError(ERR_ERROR, "[%s] Error retrieving next credential set to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }
  else if (psCredSet->psUser)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s user: %s", MODULE_NAME, psLogin->psServer->pHostIP, psCredSet->psUser->pUser);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s - no more available users to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }

  memset(&params, 0, sizeof(sConnectParams));
  if (psLogin->psServer->psAudit->iPortOverride > 0)
    params.nPort = psLogin->psServer->psAudit->iPortOverride;
  else
    params.nPort = PORT_VNC;
  initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        while (!bAuthAllowed)
        {
          if (hSocket > 0)
            medusaDisconnect(hSocket);
  
          hSocket = medusaConnect(&params);
        
          if (hSocket < 0) 
          {
            writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
            psLogin->iResult = LOGIN_RESULT_UNKNOWN;
            return FAILURE;
          }

          writeError(ERR_DEBUG_MODULE, "Connected");

          iRet = vncSessionSetup(hSocket, (unsigned char*) &zChallenge);
          switch( iRet )
          {
            case SESSION_SUCCESS:
              writeError(ERR_DEBUG_MODULE, "VNC Session Initialized.");
              bAuthAllowed = TRUE;
              nState = MSTATE_RUNNING;
              break;
            case SESSION_SUCCESS_NO_AUTH:
              writeError(ERR_DEBUG_MODULE, "VNC Server Does Not Require Authentication.");
              psLogin->iResult = LOGIN_RESULT_SUCCESS;
              setPassResult(psLogin, "[NO AUTH REQUIRED]");
              bAuthAllowed = TRUE;
              nState = MSTATE_EXITING;
              break;
            case SESSION_MAX_AUTH_REALVNC:
              writeError(ERR_ALERT, "[%s] Host %s reported too many security failures. Sleeping %d seconds before next attempt.", MODULE_NAME, psLogin->psServer->pHostIP, nAngrySleep);
              if (nAngrySleep > _psSessionData->nMaxAuthSleep)
              {
                writeError(ERR_ERROR, "[%s] Host %s exceeded maximum allowed sleep. Terminating connection.", MODULE_NAME, psLogin->psServer->pHostIP);
                psLogin->iResult = LOGIN_RESULT_UNKNOWN;
                bAuthAllowed = TRUE;
                nState = MSTATE_EXITING;
              }
              else
              {
                sleep(nAngrySleep + 1);
                nAngrySleep = 2 * nAngrySleep;
              }
              break;
            case SESSION_MAX_AUTH_ULTRAVNC:
              writeError(ERR_ALERT, "[%s] Host %s has rejected the connection. Sleeping 10 seconds before next attempt.", MODULE_NAME, psLogin->psServer->pHostIP);
              if (nAngrySleep > _psSessionData->nMaxAuthSleep)
              {
                writeError(ERR_ERROR, "[%s] Host %s exceeded maximum allowed sleep. Terminating connection.", MODULE_NAME, psLogin->psServer->pHostIP);
                psLogin->iResult = LOGIN_RESULT_UNKNOWN;
                bAuthAllowed = TRUE;
                nState = MSTATE_EXITING;
              }
              else
              {
                sleep(10 + 1);
                nAngrySleep = nAngrySleep + 10;
              }
              break;
            default:
              writeError(ERR_DEBUG_MODULE, "VNC Session Setup Failed.");
              psLogin->iResult = LOGIN_RESULT_UNKNOWN;
              bAuthAllowed = TRUE;
              nState = MSTATE_EXITING;
              break;
          }
        }

        bAuthAllowed = FALSE;
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(hSocket, &psLogin, _psSessionData, (unsigned char*) &zChallenge, psCredSet->pPass);

        if (psLogin->iResult != LOGIN_RESULT_UNKNOWN)
        {
          if (getNextCredSet(psLogin, psCredSet) == FAILURE)
          {
            writeError(ERR_ERROR, "[%s] Error retrieving next credential set to test.", MODULE_NAME);
            nState = MSTATE_EXITING;
          }
          else
          {
            if (psCredSet->iStatus == CREDENTIAL_DONE)
            {
              writeError(ERR_DEBUG_MODULE, "[%s] No more available credential sets to test.", MODULE_NAME);
              nState = MSTATE_EXITING;
            }
            else if (psCredSet->iStatus == CREDENTIAL_NEW_USER)
            {
              writeError(ERR_DEBUG_MODULE, "[%s] Starting testing for new user: %s.", MODULE_NAME, psCredSet->psUser->pUser);
              nState = MSTATE_NEW;
            }
            else
              writeError(ERR_DEBUG_MODULE, "[%s] Next credential set - user: %s password: %s", MODULE_NAME, psCredSet->psUser->pUser, psCredSet->pPass);
          }
        }
        break;
      case MSTATE_EXITING:
        if (hSocket > 0)
          medusaDisconnect(hSocket);
        hSocket = -1;
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module state %d", MODULE_NAME, nState);
        if (hSocket > 0)
          medusaDisconnect(hSocket);
        hSocket = -1;
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }  
  }

  FREE(psCredSet);
  return SUCCESS;
}

/* VNC Specific Functions */

/*
** Encrypt CHALLENGE_SIZE bytes in memory using a password.
** Ripped from vncauth.c
*/
void vncEncryptBytes(unsigned char *bytes, char *passwd)
{
  unsigned char key[8];
  int i;

  /* key is simply password padded with nulls */
  for (i = 0; i < 8; i++) {
    if (i < strlen(passwd)) {
      key[i] = passwd[i];
    } else {
      key[i] = 0;
    }
  }
  deskey(key, EN0);
  for (i = 0; i < CHALLENGE_SIZE; i += 8) {
    des(bytes + i, bytes + i);
  }
}

int vncSessionSetup(int hSocket, unsigned char* pzChallenge)
{
  char ProtocolVersion[12];
  int iServerProtocolVersion;
  char* bufReceive;
  int nReceiveBufferSize = 0;
  
  memset(ProtocolVersion, 0, 12);
  memset(pzChallenge, 0, 16);
  
  /* Retreive server VNC protocol version */
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
    return SESSION_FAILURE;

  writeError(ERR_DEBUG_MODULE, "VNC Server Protocol Version: %s", bufReceive);

  /* The following message is triggered by 5 failed authentication attempts, at which 
  ** point a 10 second lockout is applied before the next attempt is permitted.  The
  ** next failed attempt causes the timeout to be doubled. */
  if ((strncmp(bufReceive + 20, "Too many security failures", 10) == 0) || (strncmp(bufReceive + 20, "Too many authentication failures", 10) == 0))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Host reported too many security failures.", MODULE_NAME);
    return SESSION_MAX_AUTH_REALVNC;
  }
  /*
  ** VNC Protocol Version 3: (20 bytes) 00 00 00 02 CHALLENGE[16]
  */
  else if (strncmp(bufReceive, "RFB 003.003", 11) == 0)
  {
    memcpy(ProtocolVersion, "RFB 003.003\n", 12);
    iServerProtocolVersion = 3;
  }
  /* VNC Protocol Version 7 (RealVNC)
  ** Server: (2 bytes)  01 02
  ** Client: (1 bytes)  02
  ** Server: (16 bytes) CHALLENGE
  */
  else if (strncmp(bufReceive, "RFB 003.007", 11) == 0)
  {
    memcpy(ProtocolVersion, "RFB 003.007\n", 12);
    iServerProtocolVersion = 7;
  }
  /*

  */
  else if (strncmp(bufReceive, "RFB 004.000", 11) == 0)
  {
    writeError(ERR_DEBUG_MODULE, "Unsupported VNC verions (RFB 004.000).");
    return SESSION_FAILURE;
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Unknown session setup response: %s. Setting client response to version 3.", MODULE_NAME, bufReceive);
    memcpy(ProtocolVersion, "RFB 003.003\n", 12);
    iServerProtocolVersion = 3;
  }

  /* Send client VNC protocol version */
  writeError(ERR_DEBUG_MODULE, "VNC Client Protocol Version: %s", ProtocolVersion);
  if (medusaSend(hSocket, ProtocolVersion, 12, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }
 
  /* Some VNC servers seem to get upset if we go too fast. Sleeping 1/2 second seems to help. */
  usleep(0.5 * 1000000);
  
  /* Retreive VNC protocol authentication scheme response */
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if ((bufReceive == NULL) || (nReceiveBufferSize < 4))
  {
    writeError(ERR_DEBUG_MODULE, "Invalid session response (%d): %s.", nReceiveBufferSize, bufReceive);
    return SESSION_FAILURE;
  }
  else
  {
    switch (bufReceive[3])
    {
      case 0x00:  /* connection failure */
        writeError(ERR_DEBUG_MODULE, "VNC Session Setup - Failed.");
        /* Server is probably in anti-brute force mode (UltraVNC) */
        return SESSION_MAX_AUTH_ULTRAVNC;
        break;
      case 0x01:  /* no authentication required */
        writeError(ERR_DEBUG_MODULE, "VNC Session Setup - Successful - No Authentication Required.");
        return SESSION_SUCCESS_NO_AUTH;
        break;
      case 0x02:  /* authentication required -- set authentication challenge */
        writeError(ERR_DEBUG_MODULE, "VNC Session Setup - Successful.");
        if (nReceiveBufferSize == 20)
        {
          memcpy(pzChallenge, bufReceive + 4, 16);
          writeError(ERR_DEBUG_MODULE, "VNC authentication challenge: %s", pzChallenge);
          return SESSION_SUCCESS;
        }
        else
        {
          writeError(ERR_ERROR, "[%s] Unknown session challenge. Possible unsupported authentication type.", MODULE_NAME);
          return SESSION_FAILURE;
        }
        break;
      default: /* unknown response */
        writeError(ERR_ERROR, "[%s] VNC Session Setup - Unknown Response: %d", MODULE_NAME, bufReceive[3]);
        return SESSION_FAILURE;
        break;
    }
  }

  return SESSION_FAILURE;
}

int tryLogin(int hSocket, sLogin** psLogin, _VNC_DATA* _psSessionData, unsigned char* pzChallenge, char* szPassword)
{
  char* bufReceive;
  int nReceiveBufferSize = 0;
  int iRet;

  writeError(ERR_DEBUG_MODULE, "[%s] VNC authentication challenge: %s", MODULE_NAME, pzChallenge);
  vncEncryptBytes(pzChallenge, szPassword);
  writeError(ERR_DEBUG_MODULE, "[%s] VNC authentication response: %s", MODULE_NAME, pzChallenge);

  if (medusaSend(hSocket, pzChallenge, 16, 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
    return FAILURE;

  switch (bufReceive[3])
  {
    case 0x00:
      writeError(ERR_DEBUG_MODULE, "[%s] VNC Authentication - Success", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_SUCCESS; 
      iRet = MSTATE_EXITING;
      break;
    case 0x01:
      writeError(ERR_DEBUG_MODULE, "[%s] VNC Authentication - Failed", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      iRet = MSTATE_NEW;
      break;
    default:
      writeError(ERR_ERROR, "[%s] VNC Authentication - Unknown Response: %d", MODULE_NAME, bufReceive[3]);
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      iRet = MSTATE_EXITING;
      break;
  }
  
  setPassResult((*psLogin), szPassword);

  return(iRet);
}
