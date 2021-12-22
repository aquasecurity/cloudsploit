const expect = require('chai').expect;
var lexAudioLogsEncrypted = require('./lexAudioLogsEncrypted');


const listBots = [
    {
        "botId": "ESPNGEMBCT",
        "botName": "Siri",
        "botStatus": "Available",
        "lastUpdatedDateTime": "2021-12-15T12:35:22.123000+05:00"
    }
];

const listBotAliases = [  
    {
        "botAliasId": "TSTALIASID",
        "botAliasName": "TestBotAlias",
        "description": "test bot alias",
        "botVersion": "DRAFT",
        "botAliasStatus": "Available",
        "creationDateTime": "2021-12-15T12:35:22.616000+05:00",
        "lastUpdatedDateTime": "2021-12-15T12:35:55.138000+05:00"
    },
    {
        "botAliasId": "TSTALIASAD",
        "botAliasName": "mine1",
        "description": "test bot alias",
        "botVersion": "DRAFT",
        "botAliasStatus": "Available",
        "creationDateTime": "2021-12-15T12:35:22.616000+05:00",
        "lastUpdatedDateTime": "2021-12-15T12:35:55.138000+05:00"
    }
];

const describeBotAlias = [
    {
        "botAliasId": "TSTALIASID",
        "botAliasName": "TestBotAlias",
        "description": "test bot alias",
        "botVersion": "DRAFT",
        "botAliasLocaleSettings": {
            "en_US": {
                "enabled": true
            }
        },
        "conversationLogSettings": {
            "textLogSettings": [
                {
                    "enabled": true,
                    "destination": {
                        "cloudWatch": {
                            "cloudWatchLogGroupArn": "arn:aws:logs:us-east-1:000011112222:log-group:mine1",
                            "logPrefix": "aws/lex/ESPNGEMBCT/TSTALIASID/DRAFT/"
                        }
                    }
                }
            ],
            "audioLogSettings": [
                {
                    "enabled": true,
                    "destination": {
                        "s3Bucket": {
                            "kmsKeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
                            "s3BucketArn": "arn:aws:s3:::viteace-data-bucket",
                            "logPrefix": "aws/lex/ESPNGEMBCT/TSTALIASID/DRAFT/"
                        }
                    }
                }
            ]
        },
    },
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "AWS",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const listKeys = [
    {
        "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
]

const createCache = (listBots, listBotAliases,  describeBotAlias, keys, describeKey, listBotsErr, keysErr, listBotAliasesErr, describeKeyErr, describeBotAliasErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var botId = (listBots && listBots.length) ? listBots[0].botId : null;
    var botAliasId = (listBotAliases && listBotAliases.length) ? listBotAliases[0].botAliasId : null;
    return {
        lexmodelsv2: {
            listBots: {
                'us-east-1': {
                    err: listBotsErr,
                    data: listBots
                }
            },
            listBotAliases: {
                'us-east-1': {
                    [botId]: {
                        err: listBotAliasesErr,
                        data: {
                            "botAliasSummaries":listBotAliases
                        }     
                    }
                }
            },
            describeBotAlias: {
                'us-east-1': {
                    [botAliasId]: {
                        err: describeBotAliasErr,
                        data: describeBotAlias
                    }
                }
            },
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: keysErr
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: describeKeyErr,
                        data: describeKey
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        lexmodelsv2: {
            listBots: {
                'us-east-1': null
            }
        }
    };
};

describe('lexAudioLogsEncrypted', function () {
    describe('run', function () {

        it('should PASS if Lex audio logs are encrypted with desired level', function (done) {
            const cache = createCache([listBots[0]], [listBotAliases[0]], describeBotAlias[0], listKeys, describeKey[0]);
            lexAudioLogsEncrypted.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Lex audio logs are not encrypted with desired level ', function (done) {
            const cache = createCache([listBots[0]], [listBotAliases[1]], describeBotAlias[0], listKeys, describeKey[1]);
            lexAudioLogsEncrypted.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if Lex conversation log settings not enabled', function (done) {
            const cache = createCache([]);
            lexAudioLogsEncrypted.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list Lex bots', function (done) {
            const cache = createCache(null, null, null, { message: 'Unable to list LookoutVision model'});
            lexAudioLogsEncrypted.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list Lex bot aliases', function (done) {
            const cache = createCache([listBots[0]], {}, describeBotAlias[0], null, null, { message: 'Unable to query LookoutVision models'});
            lexAudioLogsEncrypted.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list bots response not found', function (done) {
            const cache = createNullCache();
            lexAudioLogsEncrypted.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache([listBots[0]], null, null, null, null, { message: "Unable to list KMS keys" });
            lexAudioLogsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});