var expect = require('chai').expect;
const kmsAppTierCmk = require('./kmsAppTierCmk');

const listKeys = [
    {
        KeyId: '60c4f21b-e271-4e97-86ae-6403618a9467',
        KeyArn: 'arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467'
    }
];

const listKeyResources = [
    {
        "Tags": [
            {
                "TagKey": "app_tier",
                "TagValue": "app_tier"
            }
        ],
        "Truncated": false
    },
    {
        "Tags": [
            {}
        ],
        "Truncated": false
    }

]

const createCache = (keys, tags) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    return {
        kms:{
            listKeys: {
                'us-east-1': {
                    data: keys
                },
            },
            listResourceTags: {
                'us-east-1': {
                    [keyId]: {
                        data: tags
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        kms: {
            listKeys: {
                'us-east-1': {
                    err: {
                        message: 'error listing kms keys'
                    },
                },
            },
            
            listKeyResources: {
                'us-east-1': {
                    err: {
                        message: 'error listing kms key resources'
                    },
                },
            },
        }
    };
};

const createNullCache = () => {
    return {
        kms: {
            listKeys: {
                'us-east-1': null,
            },
            listKeyResources: {
                'us-east-1': null
            },
        },
    };
};

describe('kmsAppTierCmk', function () {
    describe('run', function () {
        it('should FAIL if no App-Tier KMS CMK found', function (done) {
            const cache = createCache([listKeys[0]], listKeyResources[0]);
            kmsAppTierCmk.run(cache, { kms_app_tier_tag_key: 'app_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if App-Tier KMS CMK is present', function (done) {
            const cache = createCache([listKeys[0]], listKeyResources[1]);
            kmsAppTierCmk.run(cache, { kms_app_tier_tag_key: 'app_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no KMS keys found', function (done) {
            const cache = createCache([]);
            kmsAppTierCmk.run(cache, { kms_app_tier_tag_key: 'app_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createErrorCache();
            kmsAppTierCmk.run(cache, { kms_app_tier_tag_key: 'app_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if list keys response is not found', function (done) {
            const cache = createNullCache();
            kmsAppTierCmk.run(cache, { kms_app_tier_tag_key: 'app_tier' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});