var expect = require('chai').expect;
var imgBuilderComponentsEncrypted = require('./imgBuilderComponentsEncrypted');

const listComponents = [
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:component/akhtar-compo/1.0.0",
        "name": "akhtar-compo",
        "version": "1.0.0",
        "platform": "Linux",
        "type": "BUILD",
        "owner": "000011112222",
        "dateCreated": "2022-03-29T10:42:58.859Z"
    },
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:component/sadeedcomponent/1.0.0",
        "name": "sadeedcomponent",
        "version": "1.0.0",
        "platform": "Linux",
        "supportedOsVersions": [
            "Amazon Linux 2"
        ],
        "type": "BUILD",
        "owner": "000011112222",
        "dateCreated": "2022-03-24T15:31:10.328Z"
    }
];


const getComponent = [
    {
        "requestId": "c061f565-2a9c-4fb5-9eb3-be2da3816257",
        "component": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:component/akhtar-compo/1.0.0/1",
            "name": "akhtar-compo",
            "version": "1.0.0",
            "type": "BUILD",
            "platform": "Linux",
            "owner": "000011112222",
            "data": "name: HelloWorldTestingDocument\ndescription: This is hello world testing document.\nschemaVersion: 1.0\n\nphases:\n  - name: build\n    steps:\n      - name: HelloWorldStep\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Hello World! Build.\"\n\n  - name: validate\n    steps:\n      - name: HelloWorldStep\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Hello World! Validate.\"\n\n  - name: test\n    steps:\n      - name: HelloWorldStep\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Hello World! Test.\"\n",
            "kmsKeyId": "arn:aws:kms:us-east-1:000011112222:alias/akhtar-key",
            "encrypted": true,
            "dateCreated": "2022-03-29T10:42:58.859Z",
            "tags": {}
        }
    },
    {
        "requestId": "9705dd22-00d6-4e31-beec-37b3d025e943",
        "component": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:component/sadeedcomponent/1.0.0/1",
            "name": "sadeedcomponent",
            "version": "1.0.0",
            "type": "BUILD",
            "platform": "Linux",
            "supportedOsVersions": [
                "Amazon Linux 2"
            ],
            "owner": "000011112222",
            "data": "name: HelloWorldTestingDocument\ndescription: This is hello world testing document.\nschemaVersion: 1.0\n\nphases:\n  - name: build\n    steps:\n      - name: HelloWorldStep\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Hello World! Build.\"\n\n  - name: validate\n    steps:\n      - name: HelloWorldStep\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Hello World! Validate.\"\n\n  - name: test\n    steps:\n      - name: HelloWorldStep\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Hello World! Test.\"\n",
            "encrypted": true,
            "dateCreated": "2022-03-24T15:31:10.328Z",
            "tags": {}
        }
    }
];

const listAliases = [
    {
        'AliasName': 'alias/akhtar-key',
        'AliasArn': 'arn:aws:kms:us-east-1:000011112222:alias/akhtar-key',
        'TargetKeyId': '1425f881-3b10-486a-aca8-14d2649881e3',
        'CreationDate': '2022-03-29T10:22:52.016Z',
        'LastUpdatedDate': '2022-03-29T10:22:52.016Z'
    }
];

const describeKey = [
    {
        'KeyMetadata': {
            'AWSAccountId': '000011112222',
            'KeyId': '1425f881-3b10-486a-aca8-14d2649881e3',
            'Arn': 'arn:aws:kms:us-east-1:000011112222:key/1425f881-3b10-486a-aca8-14d2649881e3',
            'CreationDate': '2022-03-29T10:22:51.516Z',
            'Enabled': true,
            'Description': '',
            'KeyUsage': 'ENCRYPT_DECRYPT',
            'KeyState': 'Enabled',
            'Origin': 'AWS_KMS',
            'KeyManager': 'CUSTOMER',
            'CustomerMasterKeySpec': 'SYMMETRIC_DEFAULT',
            'KeySpec': 'SYMMETRIC_DEFAULT',
            'EncryptionAlgorithms': [Array],
            'MultiRegion': false
          }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "1425f881-3b10-486a-aca8-14d2649881e3",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/1425f881-3b10-486a-aca8-14d2649881e3",
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
        "KeyId": "1425f881-3b10-486a-aca8-14d2649881e3",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/1425f881-3b10-486a-aca8-14d2649881e3"
    }
]

const createCache = (recipe, keys, kmsAliases, getComponent, describeKey, recipeErr, kmsAliasesErr, keysErr, describeKeyErr, getComponentErr) => {

    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    var recipeArn = (recipe && recipe.length) ? recipe[0].arn: null;
    return {
        imagebuilder: {
            listComponents: {
                'us-east-1': {
                    err: recipeErr,
                    data: recipe
                },
            },
            getComponent: {
                'us-east-1': {
                    [recipeArn]: {
                        data: getComponent,
                        err: getComponentErr
                    }
                }
            }
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    data: kmsAliases,
                    err: kmsAliasesErr
                },
            },
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

describe('imgBuilderComponentsEncrypted', function () {
    describe('run', function () {
        it('should PASS if Image Builder component is encrypted with awscmk', function (done) {
            const cache = createCache([listComponents[0]], listKeys, listAliases, getComponent[0], describeKey[0]);
            imgBuilderComponentsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Image Builder component is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Image Builder component is encrypted with awskms', function (done) {
            const cache = createCache([listComponents[1]], listKeys, listAliases, getComponent[1], describeKey[1]);
            imgBuilderComponentsEncrypted.run(cache, {image_component_desired_encryption_level: 'awscmk'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Image Builder component is encrypted with');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no component version list found', function (done) {
            const cache = createCache([]);
            imgBuilderComponentsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No component version list found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for component description', function (done) {
            const cache = createCache([listComponents[0]], listKeys, listAliases, null, null, null, null, 
                null, null,  { message: "Unable to query for component description" });
            imgBuilderComponentsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for component description');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listComponents, null, null, null, null, null, null, { message: "Unable to list KMS keys" });
            imgBuilderComponentsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list KMS keys');
                done();
            });
        });
    });
})