var expect = require('chai').expect;
var imgRcpStrgVlmEncrypted = require('./imgRcpStrgVlmEncrypted');

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
        "requestId": "873a1231-de17-4321-a634-3d3b2fdb01d0",
        "imageRecipe": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:image-recipe/recipe1/1.0.0",
            "name": "recipe1",
            "platform": "Linux",
            "owner": "000011112222",
            "version": "1.0.0",
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
            "dateCreated": "2022-03-22T16:07:38.891Z",
            "tags": {},
            "workingDirectory": "/tmp",
            "additionalInstanceConfiguration": {
                "systemsManagerAgent": {
                    "uninstallAfterBuild": false
                }
            }
        }
    }

        
];


const createCache = (analyzer, getImageRecipe, analyzerErr, getImageRecipeErr) => {
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
    };
};

describe('imgRcpStrgVlmEncrypted', function () {
    describe('run', function () {
        it('should FAIL if Image recipe does not have ebs volume storage encrypted', function (done) {
            const cache = createCache([listImageRecipes[0]], getImageRecipe[0]);
            imgRcpStrgVlmEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Image recipe does not have ebs volume storage encrypted');
                done();
            });
        });

        it('should PASS if Image recipe has ebs volume storage encrypted', function (done) {
            const cache = createCache([listImageRecipes[0]], getImageRecipe[1]);
            imgRcpStrgVlmEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Image recipe has ebs volume storage encrypted');
                
                done();
            });
        });

        it('should PASS if No list image recipes found', function (done) {
            const cache = createCache([]);
            imgRcpStrgVlmEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No list image recipes found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for image recipe summary list', function (done) {
            const cache = createCache(null, null, { message: "Unable to query for image recipe summary list" });
            imgRcpStrgVlmEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for image recipe summary list');
                done();
            });
        });
    });
})