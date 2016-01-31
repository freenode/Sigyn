# Sigyn #

A Limnoria's plugin to handle various spam with network hammer

## Commands ##

    addpattern <limit> <life> <pattern> : add a permanent pattern, triggers kill & kline if called more than <limit> during <life> in seconds, use 0 as limit for immediate action
    addregexpattern <limit> <life> <pattern> : add a permanent regular expression /pattern/, triggers kill & kline if called more than <limit> during <life> in seconds, use 0 as limit for immediate action
    lspattern [--deep] <id|pattern> : search patterns inside database, use pattern's id for full information, and --deep to search on disabled pattern
    editpattern <id> <limit> <life> [<comment>] : change some values of a pattern and add a optional comment
    togglepattern <id> <boolean> : enable or disable a pattern
    lstmp [<channel>] : list computed pattern for the given <channel>
    rmtmp [<channel>] : remove computed pattern for a given <channel>
    defcon : put the bot in a agressive mode where limits are lowered and ignores are lifted
    efnet <seconds> : ask the bot to kline users list in efnetrbl on join for <seconds>
    rehash : clear internal plugin state
    oper : tell the bot to oper
    state [<channel>] [<nick>] : debug informations about internal state, for the whole ircd, a channel or a nick in a channel
    vacuum : optimize the database
    
## Behaviour ##

Sigyn is coming from https://en.wikipedia.org/wiki/Sigyn

The plugin works with TimeoutQueue ( https://github.com/ProgVal/Limnoria/blob/master/src/utils/structures.py#L308 ) : 
Queues are filled on abuses, when the length of a queue exceeds limits, kill and kline are triggered.

Limits of queues may be lowered under conditions ( same abuse repeated by various users in a channel, network abuse, etc )

Bot is able to compute spam pattern and use them against spammers for a period of time.

After being correctly configured, bot can handle attacks without human hands, most settings can be tweaked per channel.

## Configuration ##

First measure :

    defaultcapability remove protected

If you are familiar with ChanTracker, settings in config.py should be easy to understand.

    supybot.plugins.Sigyn.enable
    
Set to False, the bot will never kill, kline or dline.

    supybot.plugins.Sigyn.logChannel
    
if setted, bot announces his actions and informs about abuses detected in that channel.

