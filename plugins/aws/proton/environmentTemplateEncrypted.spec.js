var expect = require('chai').expect;
var environmentTemplateEncrypted = require('./environmentTemplateEncrypted');

const listEnvironmentTemplates = [
    {
        "arn": "arn:aws:proton:us-east-1:000111222333:environment-template/sadeed1",
        "createdAt": "2021-11-18T17:01:54.758000+05:00",
        "displayName": "call me brown boy",
        "lastModifiedAt": "2021-11-18T17:01:54.758000+05:00",
        "name": "sadeed1"
    },
    {
        "arn": "arn:aws:proton:us-east-1:000111222333:environment-template/sad1",
        "createdAt": "2021-11-18T17:36:46.281000+05:00",
        "displayName": "sadeed",
        "lastModifiedAt": "2021-11-18T17:36:46.281000+05:00",
        "name": "sad1"
    }
];

const getEnvironmentTemplate = [
    {
        "environmentTemplate": {
            "arn": "arn:aws:proton:us-east-1:000111222333:environment-template/sadeed1",
            "createdAt": "2021-11-18T17:01:54.758000+05:00",
            "displayName": "call me brown boy",
            "encryptionKey": "arn:aws:kms:us-east-1:101363889637:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "lastModifiedAt": "2021-11-18T17:01:54.758000+05:00",
            "name": "sadeed1"
        }
    }

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

const createCache = (templates, keys, getEnvironmentTemplate, describeKey, templatesErr, keysErr, describeKeyErr, getEnvironmentTemplateErr) => {
    
    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    var name = (templates && templates.length) ? templates[0].name: null;
    return {
        proton: {
            listEnvironmentTemplates: {
                'us-east-1': {
                    err: templatesErr,
                    data: templates
                },
            },
            getEnvironmentTemplate: {
                'us-east-1': {
                    [name]: {
                        data: getEnvironmentTemplate,
                        err: getEnvironmentTemplateErr
                    }
                }
            }
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

describe('environmentTemplateEncrypted', function () {
    describe('run', function () {
        it('should PASS if Proton environment template is encrypted with desired encryption level', function (done) {
            const cache = createCache([listEnvironmentTemplates[0]], listKeys, getEnvironmentTemplate[0], describeKey[0]);
            environmentTemplateEncrypted.run(cache, { proton_environmenttemplate_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Proton environment template is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listEnvironmentTemplates[1]],listKeys, getEnvironmentTemplate[0], describeKey[1]);
            environmentTemplateEncrypted.run(cache, { proton_environmenttemplate_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Proton environment template found', function (done) {
            const cache = createCache([]);
            environmentTemplateEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Proton environment template', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Proton environment template" });
            environmentTemplateEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listEnvironmentTemplates, null, null, null, { message: "Unable to list KMS keys" });
            environmentTemplateEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})
