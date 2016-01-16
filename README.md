# Sigyn #

A supybot's plugin to handle various spam with network hammer

## Commands ##

    addpattern <limit> <life> <pattern> : add a permanent pattern, which must be triggered more than <limit> during <life> in seconds, use 0 as limit for instant kline
    addregexpattern <limit> <life> <pattern> : add a permanent regular expression /pattern/, which must be triggered more than <limit> during <life> in seconds, use 0 as limit for instant kline
    lspattern [--deep] <id|pattern> : search patterns inside database, use pattern's id for full information, and --deep to search on disabled pattern
    editpattern <id> <limit> <life> [<comment>] : change some values of a pattern and add a optional comment
    togglepattern <id> <boolean> : enable or disable a pattern
    lstmp [<channel>] : list computed pattern for the given <channel>
    rmtmp [<channel>] : remove computed pattern for a given <channel>
    defcon : put the bot in defcon mode during predefined duration
    efnet <seconds> : tell the bot to kline efnet users on join for <seconds>
    rehash : clear internal plugin state
    oper : tell the bot to oper
    state [<channel>] [<nick>] : debug informations about internal state, for the whole ircd, a channel or a nick in a channel
    vacuum : optimize the database
    
## Behaviour ##

The plugin works like a stacks of temporary queues, for various abuses, per network, channel and user.
When a queue raises a limit, kill and kline are issued.

Internals triggers and limits can change over time, altered by channel abuses or external conditions.
You must keep that in mind when you change settings, they could be lowered a bit on some conditions.
You can leave the bot dealing with spam waves without human intervention.

If something brokes, rmtmp #channel or rehash will do the job, if it's settings problem, see below.

## Configuration ##

If you are familiar with ChanTracker, settings in config.py should be easy to understand.

    supybot.plugins.Sigyn.enable
    
Set to False, the bot will never kill, kline or dline.

    supybot.plugins.Sigyn.logChannel
    
if setted, bot announces his actions and informs about abuses detected in that channel.
