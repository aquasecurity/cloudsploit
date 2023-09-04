var expect = require('chai').expect;
var imageRecipeVolumeEncrypted = require('./imageRecipeVolumeEncrypted');

const listImageRecipes = [
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:image-recipe/akhtar-img-rc/1.0.0",
        "name": "akhtar-img-rc",
        "platform": "Linux",
        "owner": "000011112222",
        "parentImage": "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2-arm64/x.x.x",
        "dateCreated": "2022-03-08T10:04:38.931Z",
        "tags": {}
    },
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:image-recipe/mine3/3.0.0",
        "name": "mine3",
        "platform": "Linux",
        "owner": "000011112222",
        "parentImage": "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2-arm64/x.x.x",
        "dateCreated": "2022-05-17T09:27:41.059Z",
        "tags": {}
    },
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:image-recipe/myrecipe1/1.0.2",
        "name": "myrecipe1",
        "platform": "Linux",
        "owner": "000011112222",
        "parentImage": "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2-arm64/x.x.x",
        "dateCreated": "2022-06-22T08:33:58.556Z",
        "tags": {}
    }
];

const getImageRecipe = [
    {
        "requestId": "f82f5f6b-1ed5-49c2-86a6-1a264b7db458",
        "imageRecipe": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:image-recipe/akhtar-img-rc/1.0.2",
            "name": "akhtar-img-rc",
            "platform": "Linux",
            "owner": "000011112222",
            "version": "1.0.2",
            "components": [
                {
                    "componentArn": "arn:aws:imagebuilder:us-east-1:aws:component/amazon-cloudwatch-agent-linux/x.x.x"
                }
            ],
            "parentImage": "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2-arm64/x.x.x",
            "blockDeviceMappings": [
                {
                    "deviceName": "/dev/xvda",
                    "ebs": {
                        "encrypted": false,
                        "deleteOnTermination": true,
                        "volumeSize": 8,
                        "volumeType": "gp2"
                    }
                },
                {
                    "deviceName": "/dev/sdb",
                    "ebs": {
                        "encrypted": true,
                        "deleteOnTermination": false,
                        "kmsKeyId": "arn:aws:kms:us-east-1:000011112222:alias/aws/ebs",
                        "volumeSize": 8,
                        "volumeType": "gp2"
                    }
                }
            ],
            "dateCreated": "2022-03-08T10:42:03.172Z",
            "tags": {},
            "workingDirectory": "/tmp",
            "additionalInstanceConfiguration": {
                "systemsManagerAgent": {
                    "uninstallAfterBuild": false
                }
            }
        }
    },
    {
        "requestId": "ebeb7bb6-9ff6-43b5-aaf7-40f3f6c5f0e3",
        "imageRecipe": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:image-recipe/mine3/3.0.0",
            "name": "mine3",
            "platform": "Linux",
            "owner": "000011112222",
            "version": "3.0.0",
            "components": [
                {
                    "componentArn": "arn:aws:imagebuilder:us-east-1:aws:component/amazon-cloudwatch-agent-linux/x.x.x"
                },
                {
                    "componentArn": "arn:aws:imagebuilder:us-east-1:aws:component/chrony-time-configuration-test/x.x.x"
                }
            ],
            "parentImage": "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2-arm64/x.x.x",
            "blockDeviceMappings": [
                {
                    "deviceName": "/dev/xvda",
                    "ebs": {
                        "encrypted": true,
                        "deleteOnTermination": true,
                        "kmsKeyId": "arn:aws:kms:us-east-1:000011112222:alias/aws/ebs",
                        "volumeSize": 8,
                        "volumeType": "gp2"
                    }
                }
            ],
            "dateCreated": "2022-05-17T09:27:41.059Z",
            "tags": {},
            "workingDirectory": "/tmp",
            "additionalInstanceConfiguration": {
                "systemsManagerAgent": {
                    "uninstallAfterBuild": false
                }
            }
        }
    },
    {
        "requestId": "1e87da1a-92f6-4486-97dc-98a039ad4c3a",
        "imageRecipe": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:image-recipe/myrecipe1/1.0.2",
            "name": "myrecipe1",
            "platform": "Linux",
            "owner": "000011112222",
            "version": "1.0.2",
            "components": [
                {
                    "componentArn": "arn:aws:imagebuilder:us-east-1:aws:component/amazon-cloudwatch-agent-linux/x.x.x"
                },
                {
                    "componentArn": "arn:aws:imagebuilder:us-east-1:aws:component/chrony-time-configuration-test/x.x.x"
                }
            ],
            "parentImage": "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2-arm64/x.x.x",
            "blockDeviceMappings": [
                {
                    "deviceName": "/dev/xvda",
                    "ebs": {
                        "encrypted": true,
                        "deleteOnTermination": true,
                        "kmsKeyId": "arn:aws:kms:us-east-1:000011112222:alias/sadeed-k1",
                        "volumeSize": 1,
                        "volumeType": "gp2"
                    }
                }
            ],
            "dateCreated": "2022-06-22T08:33:58.556Z",
            "tags": {},
            "workingDirectory": "/tmp",
            "additionalInstanceConfiguration": {
                "systemsManagerAgent": {
                    "uninstallAfterBuild": true
                }
            }
        }
    }
    
];


const listAliases = [
    {
        "AliasName": "alias/sadeed-k1",
        "AliasArn": "arn:aws:kms:us-east-1:000111222333:alias/sadeed-k1",
        "TargetKeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "CreationDate": "2021-11-15T17:05:31.308000+05:00",
        "LastUpdatedDate": "2021-11-15T17:05:31.308000+05:00"
    },
];

var describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my kinesis video data when no other key is defined",
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
            "Description": "Default master key that protects my kinesis video data when no other key is defined",
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
];


const createCache = (analyzer, keys, kmsAliases, getImageRecipe, describeKey, analyzerErr, kmsAliasesErr, keysErr, describeKeyErr, getImageRecipeErr) => {
    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    var analyzerArn = (analyzer && analyzer.length) ? analyzer[0].arn: null;
    return {
        imagebuilder: {
            listImageRecipes: {
                'us-east-1': {
                    err: analyzerErr,
                    data: analyzer
                },
            },
            getImageRecipe: {
                'us-east-1': {
                    [analyzerArn]: {
                        data:getImageRecipe,
                        err: getImageRecipeErr
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

describe('imageRecipeVolumeEncrypted', function () {
    describe('run', function () {
        it('should PASS if Image recipe ebs volumes are encrypted with awscmk', function (done) {
            const cache = createCache([listImageRecipes[2]], listKeys, listAliases, getImageRecipe[2], describeKey[0]);
            imageRecipeVolumeEncrypted.run(cache, { image_recipe_ebs_volumes_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Image recipe ebs volumes are encrypted with awscmk'); 
                done();
            });
        });

        it('should FAIL if Image recipe ebs volumes does not have encryption enabled', function (done) {
            const cache = createCache([listImageRecipes[0]], listKeys, listAliases, getImageRecipe[0], describeKey[0]);
            imageRecipeVolumeEncrypted.run(cache, { image_recipe_ebs_volumes_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ebs volumes does not have encryption enabled');
                done();
            });
        });

        it('should FAIL if Image recipe ebs volumes are encrypted with awskms', function (done) {
            const cache = createCache([listImageRecipes[1]], listKeys, listAliases, getImageRecipe[1], describeKey[1]);
            imageRecipeVolumeEncrypted.run(cache, { image_recipe_ebs_volumes_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Image recipe ebs volumes are encrypted with awskms'); 
                done();
            });
        });

        it('should PASS if No Image Builder image recipes found', function (done) {
            const cache = createCache([]);
            imageRecipeVolumeEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Image Builder image recipes found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for image recipe summary list', function (done) {
            const cache = createCache(null, null, { message: "Unable to query for image recipe summary list" });
            imageRecipeVolumeEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for image recipe summary list');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache([listImageRecipes[0]], null, null, null, { message: "Unable to list KMS keys" });
            imageRecipeVolumeEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})