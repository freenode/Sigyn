###
# Copyright (c) 2016, Nicolas Coevoet
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

###

import supybot.conf as conf
import supybot.registry as registry
try:
    from supybot.i18n import PluginInternationalization
    _ = PluginInternationalization('Sigyn')
except:
    # Placeholder that allows to run the plugin on a bot
    # without the i18n module
    _ = lambda x:x

def configure(advanced):
    # This will be called by supybot to configure this module.  advanced is
    # a bool that specifies whether the user identified himself as an advanced
    # user or not.  You should effect your configuration by manipulating the
    # registry as appropriate.
    from supybot.questions import expect, anything, something, yn
    conf.registerPlugin('Sigyn', True)


Sigyn = conf.registerPlugin('Sigyn')

conf.registerGlobalValue(Sigyn, 'enable',
     registry.Boolean(False, """set to True to enable kill and klines, otherwise bot will only report to logChannel"""))

conf.registerGlobalValue(Sigyn, 'mainChannel',
     registry.String("#freenode","""main channel, where bot stay opped and op staffer on +z"""))

conf.registerGlobalValue(Sigyn, 'snoopChannel',
     registry.String("", """channel where services stuff are announced"""))

conf.registerGlobalValue(Sigyn, 'mxbl',
     registry.CommaSeparatedListOfStrings([''],"""patterns to match"""))

conf.registerGlobalValue(Sigyn, 'wordsList',
     registry.CommaSeparatedListOfStrings([''],"""paths of files contains one word per line"""))
conf.registerGlobalValue(Sigyn, 'wordMinimum',
    registry.PositiveInteger(4,"""minimum length of words to use for detection"""))

conf.registerGlobalValue(Sigyn, 'minimumUsersInChannel',
    registry.Integer(-1,"""if /invite enabled, ( see lastActionTaken ), bot will do /list #channel to ensure it has enough users before joining"""))

conf.registerGlobalValue(Sigyn, 'logChannel',
     registry.String("", """channel where bot's actions is announced"""))
conf.registerGlobalValue(Sigyn, 'useNotice',
     registry.Boolean(False, """use notices for announces in logChannel"""))
     
conf.registerGlobalValue(Sigyn,'resolverTimeout',
    registry.PositiveInteger(3, """max duration of dns request/resolve in seconds"""))
     
conf.registerGlobalValue(Sigyn, 'klineDuration',
     registry.Integer(-1, """kline duration, in minutes, with -1, bot will not kill or kline"""))
conf.registerGlobalValue(Sigyn, 'klineMessage',
     registry.String("Please do not spam users or channels on freenode. If in error, please contact kline@freenode.net.", """default reason used in kline's message"""))
conf.registerChannelValue(Sigyn, 'killMessage',
     registry.String("Spam is off topic on freenode.", """kill reason"""))
     
conf.registerGlobalValue(Sigyn, 'operatorNick',
     registry.String("", """oper's nick, must be filled""", private=True))
conf.registerGlobalValue(Sigyn, 'operatorPassword',
     registry.String("", """oper's password, must be filled""", private=True))

conf.registerGlobalValue(Sigyn, 'alertPeriod',
    registry.PositiveInteger(1,"""interval between 2 alerts of same type in logChannel"""))
conf.registerGlobalValue(Sigyn, 'netsplitDuration',
    registry.PositiveInteger(1,"""duration of netsplit ( which disable some protections )"""))

conf.registerGlobalValue(Sigyn, 'alertOnWideKline',
    registry.Integer(-1,"""alert if a kline hits more than expected users"""))

conf.registerGlobalValue(Sigyn, 'decloakPermit',
    registry.Integer(-1,"""-1 to disable, alert in logChannel if limit reached"""))
conf.registerGlobalValue(Sigyn, 'decloakLife',
    registry.PositiveInteger(1,"""duration of stored akick add/del in seconds"""))

conf.registerGlobalValue(Sigyn, 'lagPermit',
     registry.Integer(-1, """max lag allowed in seconds, otherwise entering netsplit mode"""))
conf.registerGlobalValue(Sigyn, 'lagInterval',
     registry.PositiveInteger(1, """interval between two check about lag, also used to garbage collect useless items in internal state"""))

conf.registerGlobalValue(Sigyn, 'serverFilteringPermit',
     registry.Integer(-1, """-1 to disable, enable dnsbling and klining when server trigger filtering messages"""))
conf.registerGlobalValue(Sigyn, 'serverFilteringLife',
     registry.PositiveInteger(1, """life of message in buffer in seconds"""))

conf.registerGlobalValue(Sigyn, 'ghostPermit',
     registry.Integer(-1, """max number of ghost connections allowed"""))

conf.registerGlobalValue(Sigyn, 'saslPermit',
    registry.Integer(-1,"""sasl attempts allowed, -1 to disable"""))
conf.registerGlobalValue(Sigyn, 'saslLife',
     registry.PositiveInteger(300, """life of messages to keep"""))
conf.registerGlobalValue(Sigyn, 'saslDuration',
     registry.PositiveInteger(240, """dline duration in minutes"""))
conf.registerGlobalValue(Sigyn, 'saslMessage',
     registry.String("Banned due to too many failed login attempts in a short period, email kline@freenode.net when corrected. Thanks!", """dline message"""))

conf.registerChannelValue(Sigyn, 'lastActionTaken',
     registry.Float(0.0, """store date of last action taken in a channel"""))
conf.registerChannelValue(Sigyn, 'leaveChannelIfNoActivity',
     registry.Integer(-1, """leave channel after days of inactivity, -1 to disable"""))

conf.registerGlobalValue(Sigyn, 'announcePermit',
    registry.Integer(-1,"""number of announce permit in logChannel,if triggered the bot will stay quiet for alertPeriod, -1 to disable"""))
conf.registerGlobalValue(Sigyn, 'announceLife',
    registry.PositiveInteger(1,"""life of announce in memory (seconds)"""))

conf.registerGlobalValue(Sigyn, 'ipv4AbusePermit',
     registry.Integer(-1, """check /24 on ipv4 klines made by the bot, -1 to disable, if triggered, announce in logChannel"""))
conf.registerGlobalValue(Sigyn, 'ipv4AbuseLife',
     registry.PositiveInteger(1, """life duration of those kline in seconds"""))

conf.registerGlobalValue(Sigyn, 'useWhoWas',
     registry.Boolean(False, """use whowas for resolving ip"""))

conf.registerGlobalValue(Sigyn, 'useOperServ',
     registry.Boolean(False, """use OperServ AKILL instead of KLINE"""))

conf.registerGlobalValue(Sigyn,'msgInviteConfirm',
     registry.String("Your request has been submitted to freenode staff.","""sent to op who requested /invite"""))

conf.registerGlobalValue(Sigyn,'msgTooManyGhost',
     registry.String("Banned due to too many connections in a short period, email kline@freenode.net when corrected.","""sent to op who requested /invite"""))

conf.registerGlobalValue(Sigyn,'staffCloak',
     registry.String("freenode/staff/","""used to identify staffers"""))

# to fight some specific spambot
conf.registerGlobalValue(Sigyn, 'channelCreationPermit',
    registry.Integer(-1,"""-1 to disable, announce always, kline on defcon"""))
conf.registerGlobalValue(Sigyn, 'channelCreationLife',
     registry.PositiveInteger(60, """life of messages to keep"""))
conf.registerGlobalValue(Sigyn, 'lethalChannels',
    registry.CommaSeparatedListOfStrings([''],"""patterns to match"""))

# dronebl submit
conf.registerGlobalValue(Sigyn, 'droneblKey',
     registry.String("", """dronebl key for rpc calls""", private=True))
conf.registerGlobalValue(Sigyn, 'droneblHost',
     registry.String("http://dronebl.org/RPC2", """where bot must do rpc calls"""))
conf.registerGlobalValue(Sigyn, 'droneblPatterns',
    registry.CommaSeparatedListOfStrings([''],"""patterns to match"""))

conf.registerGlobalValue(Sigyn, 'secretChannel',
    registry.String("","""secretChannel"""))
# report
conf.registerGlobalValue(Sigyn, 'reportChannel',
    registry.String("","""channel of the instance"""))
conf.registerGlobalValue(Sigyn, 'reportNicks',                                                                                                                                                                                      
    registry.CommaSeparatedListOfStrings([''],"""bots nicks"""))
conf.registerGlobalValue(Sigyn, 'reportPermit',
    registry.Integer(-1,"""number of proxy detected, -1 to disable"""))
conf.registerGlobalValue(Sigyn, 'reportLife',
    registry.PositiveInteger(1,"""life duration of proxies, in seconds"""))
conf.registerGlobalValue(Sigyn, 'defcon',
    registry.PositiveInteger(1,"""duration of defcon mode in seconds, where bot is more agressive, with lowered abuse triggers and no ignores"""))

# amsg
conf.registerGlobalValue(Sigyn, 'amsgMinimum',
    registry.PositiveInteger(1,"""length of text necessary to start amsg check"""))
conf.registerGlobalValue(Sigyn, 'amsgPermit',
    registry.Integer(-1,"""number of channels allowed with same message"""))
conf.registerGlobalValue(Sigyn, 'amsgLife',
    registry.PositiveInteger(1,"""life of channels in seconds"""))
conf.registerGlobalValue(Sigyn, 'amsgPercent',
    registry.Probability(1.00,"""percent of similarity between two messages"""))

# service notices 

# user nick changes snote
conf.registerGlobalValue(Sigyn, 'nickChangePermit',
    registry.Integer(-1,"""number of server notices (nick changes) allowed for a given period"""))
conf.registerGlobalValue(Sigyn, 'nickChangeLife',
    registry.PositiveInteger(1,"""life of notices in seconds"""))

# channel flood snote
conf.registerGlobalValue(Sigyn, 'channelFloodPermit',
    registry.Integer(-1,"""number of server notices (possible flooder) from various host allowed for a given channel"""))
conf.registerGlobalValue(Sigyn, 'channelFloodLife',
    registry.PositiveInteger(1,"""life of notices in seconds"""))

# user flood snote
conf.registerGlobalValue(Sigyn, 'userFloodPermit',
    registry.Integer(-1,"""number of snotes about flood targeted a given user with differents hosts"""))
conf.registerGlobalValue(Sigyn, 'userFloodLife',
    registry.PositiveInteger(1,"""life of notices in seconds"""))

# join/spam snote
conf.registerGlobalValue(Sigyn, 'joinRatePermit',
    registry.Integer(-1,"""number of snotes about join floodfor a given channel with differents users"""))
conf.registerGlobalValue(Sigyn, 'joinRateLife',
    registry.PositiveInteger(1,"""life of notices in seconds"""))

conf.registerGlobalValue(Sigyn, 'crawlPermit',
    registry.Integer(-1,"""number of snotes about join floodfor a given channel with differents users"""))
conf.registerGlobalValue(Sigyn, 'crawlLife',
    registry.PositiveInteger(1,"""life of notices in seconds"""))

# NickServ ID failures
conf.registerGlobalValue(Sigyn, 'idPermit',
    registry.Integer(-1,"""number of snotes about id failure from a given user and different account"""))
conf.registerGlobalValue(Sigyn, 'idLife',
    registry.PositiveInteger(1,"""life duration of message in those snote"""))

conf.registerGlobalValue(Sigyn, 'registerPermit',
    registry.Integer(-1,"""number of register allowed per ip during registerLife"""))
conf.registerGlobalValue(Sigyn, 'registerLife',
    registry.PositiveInteger(1,"""life of notices in seconds"""))

# change modes on defcon
conf.registerChannelValue(Sigyn, 'defconMode',
    registry.Boolean(False,"""changes +qz $~a -qz $~a on defcon"""))

# unicode exploits
conf.registerChannelValue(Sigyn, 'badunicodeLimit',
    registry.Integer(-1,"""score of message with bad unicode limit"""))
conf.registerChannelValue(Sigyn, 'badunicodePermit',
    registry.Integer(-1,"""number bad unicode message allowed"""))
conf.registerChannelValue(Sigyn, 'badunicodeLife',
    registry.PositiveInteger(1,"""life of bad unicode message"""))
conf.registerChannelValue(Sigyn, 'badunicodeScore',
    registry.PositiveInteger(1,"""score of message to trigger limit"""))

# Quit flood
conf.registerChannelValue(Sigyn, 'brokenPermit',
    registry.Integer(-1,"""number of quit allowed"""))
conf.registerChannelValue(Sigyn, 'brokenLife',
    registry.PositiveInteger(1,"""life duration of buffer for broken client detection"""))
conf.registerChannelValue(Sigyn, 'brokenDuration',
    registry.PositiveInteger(1,"""kline duration in minutes"""))
conf.registerChannelValue(Sigyn, 'brokenReason',
    registry.String("Your irc client seems broken and is flooding lots of channels. Banned for %s min, if in error, please contact kline@freenode.net.","""kline reason"""))
conf.registerChannelValue(Sigyn, 'brokenHost',
    registry.CommaSeparatedListOfStrings([''], """list of knowns broken host"""))

# ignores feature
conf.registerChannelValue(Sigyn, 'ignoreRegisteredUser',
     registry.Boolean(False, """ignore registered users in the channel"""))
conf.registerChannelValue(Sigyn, 'ignoreChannel',
     registry.Boolean(False, """ignore everything in the channel"""))
conf.registerChannelValue(Sigyn, 'ignoreVoicedUser',
     registry.Boolean(False, """ignore voiced users in the channel"""))
conf.registerChannelValue(Sigyn, 'ignoreDuration',
     registry.Integer(-1, """in secondes: if -1 disabled, otherwise bot ignores user's privmsg/notices after <seconds> in channel"""))

# abuses lowered thresold for given channel and a given abuse, and lift ignores
conf.registerChannelValue(Sigyn, 'abusePermit',
    registry.Integer(-1,"""-1 to disable, reduces threshold of triggers when they occurs more than abusePermit during abuseLife"""))
conf.registerChannelValue(Sigyn, 'abuseLife',
    registry.PositiveInteger(1,"""life duration of message in the buffer detection, in seconds"""))
conf.registerChannelValue(Sigyn, 'abuseDuration',
    registry.PositiveInteger(1,"""duration in seconds of abuse state"""))
    
# ignored users can still trigger klines if desired
conf.registerChannelValue(Sigyn, 'bypassIgnorePermit',
    registry.Integer(-1,"""number of triggers allowed while ignored, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'bypassIgnoreLife',
    registry.PositiveInteger(1,"""in seconds"""))

# channel protections
conf.registerChannelValue(Sigyn, 'clearTmpPatternOnUnkline',
     registry.Boolean(False, """clean channel's temporary patterns on unkline requested by channel's op"""))

conf.registerChannelValue(Sigyn, 'massJoinPermit',
    registry.Integer(-1,"""number of joins allowed during massJoinLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'massJoinLife',
    registry.PositiveInteger(1,"""life duration of messages in the massJoin detection"""))

conf.registerChannelValue(Sigyn, 'massJoinNickPermit',
    registry.Integer(-1,"""number of smiliar nick joins allowed during massJoinNickLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'massJoinNickLife',
    registry.PositiveInteger(1,"""life duration of messages in the massJoinNick detection"""))

conf.registerChannelValue(Sigyn, 'massJoinHostPermit',
    registry.Integer(-1,"""number of smiliar host joins allowed during massJoinHostLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'massJoinHostLife',
    registry.PositiveInteger(1,"""life duration of messages in the massJoinHost detection"""))

conf.registerChannelValue(Sigyn, 'massJoinGecosPermit',
    registry.Integer(-1,"""number of smiliar gecos joins allowed during massJoinGecosLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'massJoinGecosLife',
    registry.PositiveInteger(1,"""life duration of messages in the massJoinGecos detection"""))

conf.registerChannelValue(Sigyn, 'massJoinPercent',
    registry.Probability(1.00,"""percent of similarity between two pattern ( for nicks and gecos )"""))
conf.registerChannelValue(Sigyn, 'massJoinMinimum',
    registry.PositiveInteger(1,"""length of pattern to match as least"""))
    
conf.registerChannelValue(Sigyn, 'massJoinTakeAction',
     registry.Boolean(False, """takes actions against massJoin found hosts/gecos/nicks"""))

conf.registerChannelValue(Sigyn, 'floodPermit',
    registry.Integer(-1,"""number of messages allowed during floodLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'floodLife',
    registry.PositiveInteger(1,"""life duration of message in the flood buffer detection"""))
conf.registerChannelValue(Sigyn, 'floodMinimum',
    registry.PositiveInteger(1,"""minimun number of chars to enter flood detection"""))

conf.registerChannelValue(Sigyn, 'lowFloodPermit',
    registry.Integer(-1,"""number of messages allowed during lowFoodLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'lowFloodLife',
    registry.PositiveInteger(1,"""life duration of message in the lowFlood buffer detection"""))

conf.registerChannelValue(Sigyn, 'capPermit',
    registry.Integer(-1,"""number of uppercase messages allowed, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'capLife',
    registry.PositiveInteger(1,"""life duration of message in the uppercase buffer detection"""))
conf.registerChannelValue(Sigyn, 'capPercent',
    registry.PositiveInteger(80,"""percent of the message in uppercase"""))
conf.registerChannelValue(Sigyn, 'capMinimum',
    registry.PositiveInteger(1,"""minimun number of chars to enter cap detection"""))

conf.registerChannelValue(Sigyn, 'repeatPermit',
    registry.Integer(-1,"""number of repeated trigger allowed during repeatLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'repeatLife',
    registry.PositiveInteger(1,"""life duration of message in the repeat buffer detection"""))
conf.registerChannelValue(Sigyn, 'repeatPercent',
    registry.Probability(1.00,"""percent of similarity between two pattern to trigger repeat detection"""))
conf.registerChannelValue(Sigyn, 'repeatCount',
    registry.PositiveInteger(1,"""if pattern is smaller than computedPattern, bot may still add it anyway, if occured more than repeatCount"""))
conf.registerChannelValue(Sigyn, 'repeatMinimum',
    registry.PositiveInteger(1,"""minimal length of a pattern, in that case, the pattern must be repeated more than at least repeatCount in the message"""))
    
conf.registerChannelValue(Sigyn, 'lowRepeatPermit',
    registry.Integer(-1,"""number of repeated messages allowed during lowrepeatLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'lowRepeatLife',
    registry.PositiveInteger(1,"""life duration of message in the lowrepeat buffer detection"""))
conf.registerChannelValue(Sigyn, 'lowRepeatPercent',
    registry.Probability(1.00,"""percent of similarity between two messages to trigger lowrepeat detection"""))
conf.registerChannelValue(Sigyn, 'lowRepeatCount',
    registry.PositiveInteger(1,"""keep this value to 1, this settings only exist because repeat and lowrepeat use nearly the same code"""))
conf.registerChannelValue(Sigyn, 'lowRepeatMinimum',
    registry.PositiveInteger(1,"""minimun number of chars to enter lowRepeat detection"""))

conf.registerChannelValue(Sigyn, 'massRepeatPermit',
    registry.Integer(-1,"""number of mass repeat permit duration massRepeatLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'massRepeatLife',
    registry.PositiveInteger(1,"""Duration of messages's life in massRepeat counter, in seconds"""))
conf.registerChannelValue(Sigyn, 'massRepeatPercent',
    registry.Probability(1.00,"""percentage similarity between previous and current message to trigger a massRepeat count"""))
conf.registerChannelValue(Sigyn, 'massRepeatMinimum',
    registry.PositiveInteger(1,"""minimum number of chars to enter massRepeat detection"""))

conf.registerChannelValue(Sigyn, 'joinSpamPartPermit',
    registry.Integer(-1,"""number of messages before leaving channel, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'joinSpamPartLife',
    registry.PositiveInteger(1,"""duration in seconds of user presence in channel"""))



conf.registerChannelValue(Sigyn, 'computedPattern',
    registry.Integer(-1,"""minimun number of chars needed to keep it as a spam pattern, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'computedPatternLife',
    registry.PositiveInteger(1,"""life in seconds of computed pattern"""))
conf.registerChannelValue(Sigyn, 'shareComputedPatternID',
    registry.Integer(-1,"""share the temporary pattern created to all channels with the same number, -1 to disable"""))

conf.registerChannelValue(Sigyn, 'lowMassRepeatPermit',
    registry.Integer(-1,"""number of mass repeat permit duration massRepeatLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'lowMassRepeatLife',
    registry.PositiveInteger(1,"""Duration of messages's life in massRepeat counter, in seconds"""))
conf.registerChannelValue(Sigyn, 'lowMassRepeatPercent',
    registry.Probability(1.00,"""percentage similarity between previous and current message to trigger a massRepeat count"""))
conf.registerChannelValue(Sigyn, 'lowMassRepeatMinimum',
    registry.PositiveInteger(1,"""minimun number of chars to enter massRepeat detection"""))

conf.registerChannelValue(Sigyn, 'hilightNick',
    registry.Integer(-1,"""number nick allowed per message, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'hilightPermit',
    registry.Integer(-1,"""number of hilight detection allowed during hilightLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'hilightLife',
    registry.PositiveInteger(1,"""life duration of hilight buffer"""))
    
conf.registerChannelValue(Sigyn, 'lowHilightNick',
    registry.Integer(-1,"""number nick allowed per message, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'lowHilightPermit',
    registry.Integer(-1,"""number of hilight detection allowed during hilightLife, -1 to disable"""))
conf.registerChannelValue(Sigyn, 'lowHilightLife',
    registry.PositiveInteger(1,"""life duration of hilight buffer"""))

conf.registerChannelValue(Sigyn, 'cyclePermit',
    registry.Integer(-1,"""number of cycle allowed during cycleLife"""))
conf.registerChannelValue(Sigyn, 'cycleLife',
    registry.PositiveInteger(1,"""life duration of part/quit in the cycle buffer detection"""))

conf.registerChannelValue(Sigyn, 'ctcpPermit',
    registry.Integer(-1,"""number of channel's ctcp allowed"""))
conf.registerChannelValue(Sigyn, 'ctcpLife',
    registry.PositiveInteger(1,"""life duration of channel's ctcp buffer detection"""))

conf.registerChannelValue(Sigyn, 'noticePermit',
    registry.Integer(-1,"""number of channel's notice allowed"""))
conf.registerChannelValue(Sigyn, 'noticeLife',
    registry.PositiveInteger(1,"""life duration of channel's notice buffer detection"""))

conf.registerChannelValue(Sigyn, 'nickPermit',
    registry.Integer(-1,"""number of nick change allowed during cycleLife"""))
conf.registerChannelValue(Sigyn, 'nickLife',
    registry.PositiveInteger(1,"""life duration of nick changes buffer detection"""))

