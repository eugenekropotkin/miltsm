/*
  SpamBot Filter 0.9.2 (07-11-24), Copyright (C) 2007 by Eugene Kropotkin, E.Kropotkin@GMail.com

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
  
*/	       

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "libmilter/mfapi.h"

#ifndef bool
# define bool	int
# define TRUE	1
# define FALSE	0
#endif /* ! bool */


struct mlfiPriv
{
	char	*mlfi_fname;
	char	*mlfi_connectfrom;
	char	*mlfi_helofrom;
	FILE	*mlfi_fp;
};

#define MLFIPRIV	((struct mlfiPriv *) smfi_getpriv(ctx))

extern sfsistat		mlfi_cleanup(SMFICTX *, bool);

/* recipients to add and reject (set with -a and -r options) */
char *add = NULL;
char *reject = NULL;

sfsistat
mlfi_connect(ctx, hostname, hostaddr)
	 SMFICTX *ctx;
	 char *hostname;
	 _SOCK_ADDR *hostaddr;
{
	struct mlfiPriv *priv;
	char *ident;

	/* allocate some private memory */
	priv = malloc(sizeof *priv);
	if (priv == NULL)
	{
		/* can't accept this message right now */
		return SMFIS_TEMPFAIL;
	}
	memset(priv, '\0', sizeof *priv);

	/* save the private data */
	smfi_setpriv(ctx, priv);

	ident = smfi_getsymval(ctx, "_");
	if (ident == NULL)
		ident = "???";
	if ((priv->mlfi_connectfrom = strdup(ident)) == NULL)
	{
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}


	// Check number of '.','-','_' - SpamBot protection at HELO stage
        int i=0,j,points,digits;    
        char bf[140];
        strncpy(bf,hostname,128);
        j=strlen(bf);
	points=0;
//	digits=0;
        if(j>3)
        {
	    while( (i<32)&&(bf[i])&&(bf[i]!=','))
	    {
//		if( (bf[i]>0x2F) && (bf[i]<0x3A)   ) digs++;
	        if( bf[i]=='.' )  points++;
	        if( bf[i]=='-' )  points++;
	        if( bf[i]=='_' )  points++;
	        i++;
	    }
	};

//05.09.2008	- reject added
	if(points>6)
	{
            fprintf(stderr, "dbg.helo: len=%i <%s> %i - FAIL Points.H1\r\n", j, bf, points);
//	    return SMFIS_DISCARD;
	    return SMFIS_REJECT;
	};

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
mlfi_helo(ctx, helohost)
	 SMFICTX *ctx;
	 char *helohost;
{
	size_t len;
	char *tls;
	char *buf;
	struct mlfiPriv *priv = MLFIPRIV;

	tls = smfi_getsymval(ctx, "{tls_version}");
	if (tls == NULL)
		tls = "No TLS";
	if (helohost == NULL)
		helohost = "???";
	len = strlen(tls) + strlen(helohost) + 3;
	if ((buf = (char*) malloc(len)) == NULL)
	{
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}
	snprintf(buf, len, "%s, %s", helohost, tls);
	if (priv->mlfi_helofrom != NULL)
		free(priv->mlfi_helofrom);
	priv->mlfi_helofrom = buf;

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
mlfi_envfrom(ctx, argv)
	 SMFICTX *ctx;
	 char **argv;
{
	int fd = -1;
	int argc = 0;
	struct mlfiPriv *priv = MLFIPRIV;
	char *mailaddr = smfi_getsymval(ctx, "{mail_addr}");

	/* open a file to store this message */
	if ((priv->mlfi_fname = strdup("/tmp/msg.XXXXXXXX")) == NULL)
	{
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}

	if ((fd = mkstemp(priv->mlfi_fname)) == -1)
	{
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}

	if ((priv->mlfi_fp = fdopen(fd, "w+")) == NULL)
	{
		(void) close(fd);
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}

	/* count the arguments */
	while (*argv++ != NULL)
		++argc;

	/* log the connection information we stored earlier: */
	if (fprintf(priv->mlfi_fp, "Connect from %s (%s)\n\n",
		    priv->mlfi_helofrom, priv->mlfi_connectfrom) == EOF)
	{
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}
	/* log the sender */
	if (fprintf(priv->mlfi_fp, "FROM %s (%d argument%s)\n",
		    mailaddr ? mailaddr : "???", argc,
		    (argc == 1) ? "" : "s") == EOF)
	{
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
mlfi_envrcpt(ctx, argv)
	 SMFICTX *ctx;
	 char **argv;
{
	struct mlfiPriv *priv = MLFIPRIV;
	char *rcptaddr = smfi_getsymval(ctx, "{rcpt_addr}");
	int argc = 0;
	
	int pass=0;
	int local=0;
	int digs=0;
	int points=0;
	int hostsz=0;
	
	int rppp=0;
	int rdsl=0;

	/* count the arguments */
	while (*argv++ != NULL)
		++argc;

	/* log this recipient */
	if (reject != NULL && rcptaddr != NULL &&
	    (strcasecmp(rcptaddr, reject) == 0))
	{
		if (fprintf(priv->mlfi_fp, "RCPT %s -- REJECTED\n",
			    rcptaddr) == EOF)
		{
			(void) mlfi_cleanup(ctx, FALSE);
			return SMFIS_TEMPFAIL;
		}
		return SMFIS_REJECT;
	}
	if (fprintf(priv->mlfi_fp, "RCPT %s (%d argument%s)\n",
		    rcptaddr ? rcptaddr : "???", argc,
		    (argc == 1) ? "" : "s") == EOF)
	{
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}
	
	fprintf(stderr, "dbg.envrcpt helo=[%s] connect=[%s] (%s) ---- ", priv->mlfi_helofrom, priv->mlfi_connectfrom);
	fprintf(stderr, "mailaddr=[%s]   ", smfi_getsymval(ctx, "{mail_addr}"));
	fprintf(stderr, "mailhost=[%s]   ", smfi_getsymval(ctx, "{mail_host}"));
	fprintf(stderr, "mailer=[%s]  ", smfi_getsymval(ctx, "{mail_mailer}"));

	char *ma1 = smfi_getsymval(ctx, "{mail_mailer}");
	char ch1,ch2;
	
	if(ma1!=NULL)
	{	    
	    if(ma1[0]=='l')
	    {
		if(ma1[1]=='o') {local=1;};
	    };    
	};

	if(smfi_getsymval(ctx, "{mail_addr}")!=NULL)
	{	    
	    hostsz=strlen(smfi_getsymval(ctx, "{mail_host}"));
	    fprintf(stderr, "hslen=%i  ", hostsz);
	};
	
	if(!local)
	{
	    int i=0,j;
	    char bf[140];
	    strncpy(bf,priv->mlfi_helofrom,128);

	    j=strlen(bf);
	    //fprintf(stderr, "debug1 len=%i\n", j);
	    
	    if(j>3)
	    {
		while( (i<64)&&(priv->mlfi_helofrom[i]))
		{
		    if( (priv->mlfi_helofrom[i]>0x2F) && (priv->mlfi_helofrom[i]<0x3A)   ) digs++;
		    if( priv->mlfi_helofrom[i]=='.' )  points++;
		    if( priv->mlfi_helofrom[i]=='-' )  points++;
		    if( priv->mlfi_helofrom[i]=='_' )  points++;
		    if( (priv->mlfi_helofrom[i]=='d')&&(priv->mlfi_helofrom[i+1]=='s')&&(priv->mlfi_helofrom[i+2]=='l') )  rdsl++;
		    if( (priv->mlfi_helofrom[i]=='p')&&(priv->mlfi_helofrom[i+1]=='p')&&(priv->mlfi_helofrom[i+2]=='p') )  rppp++;
		    i++;
		}
	    }
	    else { digs=10; };
	    
	    // below 3????
	
	};

	fprintf(stderr, " ::: pass=%i  local=%i  digs=%i  points=%i dsl=%i ppp=%i", pass,local,digs,points,rdsl,rppp);

        if( rdsl+rppp )
        {
	    //(void) mlfi_cleanup(ctx, FALSE);
    	    fprintf(stderr, " result = !!! FAIL PPP/DSL (bad-word filter)\n\n");
	    return SMFIS_REJECT;
	};
	

	if(local)
	{
    	    fprintf(stderr, " result = !!! LOCAL pass\n\n");
	    return SMFIS_CONTINUE;
	};

//	if(hostsz>18)
//	{
//    	    fprintf(stderr, " result = !!! FAIL HostSz\n\n");
//	    //return SMFIS_TEMPFAIL;
//	    return SMFIS_DISCARD;
//	    return SMFIS_REJECT;
//	};


        if( digs>6 )
        {
	    //(void) mlfi_cleanup(ctx, FALSE);
    	    fprintf(stderr, " result = !!! FAIL PLD\n\n");
//	    return SMFIS_DISCARD;
	    return SMFIS_REJECT;
//	    return SMFIS_TEMPFAIL;
	};

	if(pass)
	{
    	    fprintf(stderr, " result = !!! pass\n\n");
//	    return SMFIS_REJECT;
	    return SMFIS_CONTINUE;
	};

/*	if( !points )
	{
    	    fprintf(stderr, "  result = !!! FAIL 1-Points\n\n");
	    return SMFIS_DISCARD;
//	    return SMFIS_REJECT;
//	    return SMFIS_TEMPFAIL;
	};/**/

	if( points>4 )
	{
    	    fprintf(stderr, "  result = !!! FAIL 2-Points\n\n");
//	    return SMFIS_DISCARD;
	    return SMFIS_REJECT;
//	    return SMFIS_TEMPFAIL;
	};

        fprintf(stderr, "debug1 = !!! unfiltered pass\n\n");
        return SMFIS_CONTINUE;
}

sfsistat
mlfi_header(ctx, headerf, headerv)
	 SMFICTX *ctx;
	 char *headerf;
	 unsigned char *headerv;
{
	/* write the header to the log file */
	if (fprintf(MLFIPRIV->mlfi_fp, "%s: %s\n", headerf, headerv) == EOF)
	{
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
mlfi_eoh(ctx)
	 SMFICTX *ctx;
{
	/* output the blank line between the header and the body */
	if (fprintf(MLFIPRIV->mlfi_fp, "\n") == EOF)
	{
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
mlfi_body(ctx, bodyp, bodylen)
	 SMFICTX *ctx;
	 unsigned char *bodyp;
	 size_t bodylen;
{
        struct mlfiPriv *priv = MLFIPRIV;

	/* output body block to log file */
	if (fwrite(bodyp, bodylen, 1, priv->mlfi_fp) != 1)
	{
		/* write failed */
		fprintf(stderr, "Couldn't write file %s: %s\n",
			priv->mlfi_fname, strerror(errno));
		(void) mlfi_cleanup(ctx, FALSE);
		return SMFIS_TEMPFAIL;
	}

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat
mlfi_eom(ctx)
	 SMFICTX *ctx;
{
	bool ok = TRUE;

	/* change recipients, if requested */
	if (add != NULL)
		ok = (smfi_addrcpt(ctx, add) == MI_SUCCESS);
	return mlfi_cleanup(ctx, ok);
}

sfsistat
mlfi_abort(ctx)
	 SMFICTX *ctx;
{
	return mlfi_cleanup(ctx, FALSE);
}

sfsistat
mlfi_cleanup(ctx, ok)
	 SMFICTX *ctx;
	 bool ok;
{
	sfsistat rstat = SMFIS_CONTINUE;
	struct mlfiPriv *priv = MLFIPRIV;
	char *p;
	char host[512];
	char hbuf[1024];

	if (priv == NULL)
		return rstat;

	/* close the archive file */
	if (priv->mlfi_fp != NULL && fclose(priv->mlfi_fp) == EOF)
	{
		/* failed; we have to wait until later */
		fprintf(stderr, "Couldn't close archive file %s: %s\n",
			priv->mlfi_fname, strerror(errno));
		rstat = SMFIS_TEMPFAIL;
		(void) unlink(priv->mlfi_fname);
	}
	else if (ok)
	{
		/* add a header to the message announcing our presence */
		if (gethostname(host, sizeof host) < 0)
			snprintf(host, sizeof host, "localhost");
		p = strrchr(priv->mlfi_fname, '/');
		if (p == NULL)
			p = priv->mlfi_fname;
		else
			p++;
		snprintf(hbuf, sizeof hbuf, "%s@%s", p, host);
		if (smfi_addheader(ctx, "X-Archived", hbuf) != MI_SUCCESS)
		{
			/* failed; we have to wait until later */
			fprintf(stderr,
				"Couldn't add header: X-Archived: %s\n",
				hbuf);
			ok = FALSE;
			rstat = SMFIS_TEMPFAIL;
			(void) unlink(priv->mlfi_fname);
		}
	}
	else
	{
		/* message was aborted -- delete the archive file */
		fprintf(stderr, "Message aborted.  Removing %s\n",
			priv->mlfi_fname);
		rstat = SMFIS_TEMPFAIL;
		(void) unlink(priv->mlfi_fname);
	}

	/* release private memory */
	if (priv->mlfi_fname != NULL)
		free(priv->mlfi_fname);

	/* return status */
	return rstat;
}

sfsistat
mlfi_close(ctx)
	 SMFICTX *ctx;
{
	struct mlfiPriv *priv = MLFIPRIV;

	if (priv == NULL)
		return SMFIS_CONTINUE;
	if (priv->mlfi_connectfrom != NULL)
		free(priv->mlfi_connectfrom);
	if (priv->mlfi_helofrom != NULL)
		free(priv->mlfi_helofrom);
	free(priv);
	smfi_setpriv(ctx, NULL);
	return SMFIS_CONTINUE;
}

struct smfiDesc smfilter =
{
	"SampleFilter",	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_ADDHDRS|SMFIF_ADDRCPT,
			/* flags */
	mlfi_connect,	/* connection info filter */
	mlfi_helo,	/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,	/* envelope recipient filter */
	mlfi_header,	/* header filter */
	mlfi_eoh,	/* end of header */
	mlfi_body,	/* body block filter */
	mlfi_eom,	/* end of message */
	mlfi_abort,	/* message aborted */
	mlfi_close,	/* connection cleanup */
};

static void
usage(prog)
	char *prog;
{
	fprintf(stderr,
		"Usage: %s -p socket-addr [-t timeout] [-r reject-addr] [-a add-addr]\n",
		prog);
}

int
main(argc, argv)
	 int argc;
	 char **argv;
{
	bool setconn = FALSE;
	int c;
	const char *args = "p:t:r:a:h";
	extern char *optarg;

	/* Process command line options */
	while ((c = getopt(argc, argv, args)) != -1)
	{
		switch (c)
		{
		  case 'p':
			if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal conn: %s\n",
					       optarg);
				exit(EX_USAGE);
			}
			if (smfi_setconn(optarg) == MI_FAILURE)
			{
				(void) fprintf(stderr,
					       "smfi_setconn failed\n");
				exit(EX_SOFTWARE);
			}

			/*
			**  If we're using a local socket, make sure it
			**  doesn't already exist.  Don't ever run this
			**  code as root!!
			*/

			if (strncasecmp(optarg, "unix:", 5) == 0)
				unlink(optarg + 5);
			else if (strncasecmp(optarg, "local:", 6) == 0)
				unlink(optarg + 6);
			setconn = TRUE;
			break;

		  case 't':
			if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal timeout: %s\n",
					       optarg);
				exit(EX_USAGE);
			}
			if (smfi_settimeout(atoi(optarg)) == MI_FAILURE)
			{
				(void) fprintf(stderr,
					       "smfi_settimeout failed\n");
				exit(EX_SOFTWARE);
			}
			break;

		  case 'r':
			if (optarg == NULL)
			{
				(void) fprintf(stderr,
					       "Illegal reject rcpt: %s\n",
					       optarg);
				exit(EX_USAGE);
			}
			reject = optarg;
			break;

		  case 'a':
			if (optarg == NULL)
			{
				(void) fprintf(stderr,
					       "Illegal add rcpt: %s\n",
					       optarg);
				exit(EX_USAGE);
			}
			add = optarg;
			smfilter.xxfi_flags |= SMFIF_ADDRCPT;
			break;

		  case 'h':
		  default:
			usage(argv[0]);
			exit(EX_USAGE);
		}
	}
	if (!setconn)
	{
		fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
		usage(argv[0]);
		exit(EX_USAGE);
	}
	if (smfi_register(smfilter) == MI_FAILURE)
	{
		fprintf(stderr, "smfi_register failed\n");
		exit(EX_UNAVAILABLE);
	}
	return smfi_main();
}

