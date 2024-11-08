var expect = require('chai').expect;
var dockerfileTemplateEncrypted = require('./dockerfileTemplateEncrypted');

const listContainerRecipes = [
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:container-recipe/test-dcr-image/1.0.0",
        "containerType": "DOCKER",
        "name": "test-dcr-image",
        "platform": "Linux",
        "owner": "000011112222",
        "parentImage": "amazonlinux:latest",
        "dateCreated": "2022-03-29T10:23:16.837Z",
        "tags": {}
    },
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:container-recipe/test-dcr-image1/1.0.0",
        "containerType": "DOCKER",
        "name": "test-dcr-image1",
        "platform": "Linux",
        "owner": "000011112222",
        "parentImage": "amazonlinux:latest",
        "dateCreated": "2022-03-29T10:26:05.280Z",
        "tags": {}
    },
];


const getContainerRecipe = [
    {
        "requestId": "70fcd2ec-f5d6-4beb-999b-b1376d2cc69c",
        "containerRecipe": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:container-recipe/test-dcr-image/1.0.0",
            "containerType": "DOCKER",
            "name": "test-dcr-image",
            "platform": "Linux",
            "owner": "000011112222",
            "version": "1.0.0",
            "components": [
                {
                    "componentArn": "arn:aws:imagebuilder:us-east-1:aws:component/amazon-cloudwatch-agent-linux/x.x.x"
                }
            ],
            "dockerfileTemplateData": "FROM {{{ imagebuilder:parentImage }}}\\n{{{ imagebuilder:environments }}}\\n{{{ imagebuilder:components }}}",
            "kmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/1425f881-3b10-486a-aca8-14d2649881e3",
            "encrypted": true,
            "parentImage": "amazonlinux:latest",
            "dateCreated": "2022-03-29T10:23:16.837Z",
            "tags": {},
            "targetRepository": {
                "service": "ECR",
                "repositoryName": "sadeedrep"
            }
        }
    },
    {
        "requestId": "28a69c0b-1296-4220-a755-02edac9db0ce",
        "containerRecipe": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:container-recipe/test-dcr-image1/1.0.0",
            "containerType": "DOCKER",
            "name": "test-dcr-image1",
            "platform": "Linux",
            "owner": "000011112222",
            "version": "1.0.0",
            "components": [
                {
                    "componentArn": "arn:aws:imagebuilder:us-east-1:aws:component/amazon-cloudwatch-agent-linux/x.x.x"
                }
            ],
            "dockerfileTemplateData": "FROM {{{ imagebuilder:parentImage }}}\\n{{{ imagebuilder:environments }}}\\n{{{ imagebuilder:components }}}",
            "encrypted": true,
            "parentImage": "amazonlinux:latest",
            "dateCreated": "2022-03-29T10:26:05.280Z",
            "tags": {},
            "targetRepository": {
                "service": "ECR",
                "repositoryName": "testrep"
            }
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

const createCache = (recipe, keys, kmsAliases, getContainerRecipe, describeKey, recipeErr, kmsAliasesErr, keysErr, describeKeyErr, getContainerRecipeErr) => {

    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    var recipeArn = (recipe && recipe.length) ? recipe[0].arn: null;
    return {
        imagebuilder: {
            listContainerRecipes: {
                'us-east-1': {
                    err: recipeErr,
                    data: recipe
                },
            },
            getContainerRecipe: {
                'us-east-1': {
                    [recipeArn]: {
                        data: getContainerRecipe,
                        err: getContainerRecipeErr
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

describe('dockerfileTemplateEncrypted', function () {
    describe('run', function () {
        it('should PASS if Dockerfile Template is encrypted with desired encryption level', function (done) {
            const cache = createCache([listContainerRecipes[0]], listKeys, listAliases, getContainerRecipe[0], describeKey[0]);
            dockerfileTemplateEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Dockerfile Template is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Dockerfile Template is encrypted with awskms', function (done) {
            const cache = createCache([listContainerRecipes[1]], listKeys, listAliases, getContainerRecipe[1], describeKey[1]);
            dockerfileTemplateEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Dockerfile Template is encrypted with');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if No container recipes found', function (done) {
            const cache = createCache([]);
            dockerfileTemplateEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No container recipes found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to get container recipe description', function (done) {
            const cache = createCache([listContainerRecipes[0]], listKeys, listAliases, null, null, null, null, 
                null, null,  { message: "Unable to get container recipe description" });
            dockerfileTemplateEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get container recipe description');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listContainerRecipes, null, null, null, null, null, null, { message: "Unable to list KMS keys" });
            dockerfileTemplateEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list KMS keys');
                done();
            });
        });
    });
})
