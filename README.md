# Sigyn #

A Limnoria's plugin to handle various spam with network hammer
You must install python-dnspython.

You must tweak default settings to fits your needs.

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
    state [<channel>] : debug informations about internal state, for the whole ircd or a channel
    vacuum : optimize the database
    
## Behaviour ##

Sigyn is coming from https://en.wikipedia.org/wiki/Sigyn

The plugin works with TimeoutQueue ( https://github.com/ProgVal/Limnoria/blob/master/src/utils/structures.py#L308 ) : 
Queues are filled on abuses, when the length of a queue exceeds limits, kill and kline are triggered.

Limits of queues may be lowered under conditions ( same abuse repeated by various users in a channel, network abuse, etc )

Bot is able to compute spam pattern and use them against spammers for a period of time.

After being correctly configured, bot can handle attacks without human hands, most settings can be tweaked per channel.

Default values in config.py must be modified to fits your needs.

## Configuration ##

You should take a look at tips here :

https://github.com/ncoevoet/ChanTracker#other-tips

### General ###

First measure:

    defaultcapability remove protected

User with #channel,protected capability are ignored, so you must remove from all users this capability which is given by default.

You should tell to bot to logs his actions in a channel:
    
    config supybot.plugins.Sigyn.logChannel #network-secret-channel

You could tell it to use notice on that channel:

    config supybot.plugins.Sigyn.useNotice True
    
In order to resolve hosts, python-dnspython is used, you can change the max duration of a resolve here:

    config supybot.plugins.Sigyn.resolverTimeout 3
    
You must set operatorNick and operatorPassword, bot will try to oper if both filled.
    
    config supybot.plugins.Sigyn.operatorNick
    config supybot.plugins.Sigyn.operatorPassword
    
On some detections bot will never take actions but will alert in logChannel, you can define the interval between two alert for the same problem:

    config supybot.plugins.Sigyn.alertPeriod 900
    
Lags and netsplits could have lot of impact on some protections ( flood, low flood detections ) due to burst of messages received at same time.
This is why the bot do a remote server request at regular interval to check the quality of the network.
If lags is too high, some protections are disabled ( note for your need you will probably need to change few bits on plugin.py ( do017, do015 ))

    config help supybot.plugins.Sigyn.lagInterval 
    config help supybot.plugins.Sigyn.lagPermit
    config help supybot.plugins.Sigyn.netsplitDuration

You should also change supybot.plugins.Sigyn.lagInterval to some minutes at least as it's also used for internal state cleanup.

As bot is opered, it can look at server's notices.

So it can alert in logChannel when some kline affects more than x users ( with some limitations due to server's notices & cloaks )

    config help supybot.plugins.sigyn.alertOnWideKline

To enable kline and kill on abuse, you must enable it and set a klineDuration > 0, before doing that, you should test and tweaks detection settings :

    config supybot.plugins.Sigyn.enable True
    config supybot.plugins.Sigyn.klineDuration 

### Detections ###

All those settings can be either global or customized per channel :

    config something
    config channel #mychannel something

#### Protections ####

To prevent Sigyn to monitor a particular channel:

    config channel #mychannel supybot.plugins.Sigyn.ignoreChannel True
    
To prevent Sigyn to monitor a particular user in a channel:

    register useraccount password
    admin capability add useraccount #mychannel,protected
    hostmask add useraccount *!*@something
    
You can tell Sigyn to be more laxist against someone who is in the channel long time enough:

    config supybot.plugins.Sigyn.ignoreDuration
    config channel #mychannel supybot.plugins.Sigyn.ignoreDuration

But as everything can happen ... 

    config help supybot.plugins.Sigyn.bypassIgnorePermit
    config help supybot.plugins.Sigyn.bypassIgnoreLife

#### Flood ####

For most detections you have to deal with 2 or 3 values at least, let's see with flood detection.

    config supybot.plugins.Sigyn.floodPermit <max number of message allowed>
    config supybot.plugins.Sigyn.floodLife <during x seconds>
    config help supybot.plugins.Sigyn.floodMinimum ( empty messages and digit messages bypass the minimun )
    
    config channel #mychannel supybot.plugins.Sigyn.floodPermit
    config channel #mychannel supybot.plugins.Sigyn.floodLife
    
Because some irc clients throttles messages, there is another set of flood detection you could use:

    config supybot.plugins.Sigyn.lowFloodPermit <max number of message allowed>
    config supybot.plugins.Sigyn.lowFloodLife <during x seconds>

#### Repeat ####

Sigyn can create temporary lethal pattern, there is two way to create pattern, one from a single message and the other from multiples messages.

For those pattern, minimum length is defined here :

    config supybot.plugins.Sigyn.computedPattern
    
Those patterns will stay active during (in seconds) :

    config supybot.plugins.Sigyn.computedPatternLife

Note : each time a pattern is triggered it remains active for 'computedPatternLife' seconds again

##### Single user repeat #####

Let's see the easy case, someone alone repeat same message over and over.

    config supybot.plugins.Sigyn.repeatPermit
    config supybot.plugins.Sigyn.repeatLife
    config supybot.plugins.Sigyn.repeatPercent ( 1.00 will never work, because similarity must be > at repeatPercent )

If the user raise 2/3 of the limit, bot will try to compute pattern, with this pattern creation settings.
    
    config supybot.plugins.Sigyn.repeatCount <number of occurences of the pattern in a message>
    config supybot.plugins.Sigyn.repeatPattern <minimal length of the pattern, if it occurs more than repeatCount but it is still smaller than computedPattern>

##### Repeat from various users #####

    config supybot.plugins.Sigyn.massRepeatPermit
    config supybot.plugins.Sigyn.massRepeatLife
    config supybot.plugins.Sigyn.massRepeatPercent 
    config help supybot.plugins.Sigyn.massRepeatMinimum

The main difference between both : single repeat detection could create small pattern ( so dangerous for legit users ) while massRepeat try to make the largest possible pattern. 
