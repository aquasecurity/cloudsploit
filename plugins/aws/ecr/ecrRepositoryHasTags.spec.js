var expect = require('chai').expect;
const ecrRepositoryHasTags = require('./ecrRepositoryHasTags');

const resourcegroupstaggingapi = [
    {
        "ResourceARN": "arn:aws:ecr:us-east-1:111111111111:repository/test",
        "Tags": [{key:"key1", value:"value"}],
    },
    {
        "ResourceARN": "arn:aws:ecr:us-east-1:111111111111:repository/test",
        "Tags": [],
    },
]

const describeRepositories = [
    {
        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test",
        "registryId": "111111111111",
        "repositoryName": "test",
        "repositoryUri": "111111111111.dkr.ecr.us-east-1.amazonaws.com/test",
        "createdAt": "2021-07-24T12:20:58.000Z",
        "imageTagMutability": "MUTABLE",
        "imageScanningConfiguration": {
          "scanOnPush": false
        },
        "encryptionConfiguration": {
          "encryptionType": "AES256"
        }
    },
    {
        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test",
        "registryId": "111111111111",
        "repositoryName": "test",
        "repositoryUri": "111111111111.dkr.ecr.us-east-1.amazonaws.com/test",
        "createdAt": "2021-07-24T12:20:58.000Z",
        "imageTagMutability": "IMMUTABLE",
        "imageScanningConfiguration": {
          "scanOnPush": false
        },
        "encryptionConfiguration": {
          "encryptionType": "AES256"
        }
    },
]

const createCache = (ecrRepository, rgData) => {
    return {
        ecr: {
            describeRepositories: {
                "us-east-1": {
                    data: ecrRepository
                }
            },
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
    }

}

const repositoryErrorCache = () => {
    return {
        ecr: {
            describeRepositories: {
                "us-east-1": {}
            },
        }
    }
}

describe('ecrRepositoryHasTags', () => {
    describe('run', () => {

        it('should PASS if no ecr repositories exist', () => {
            const cache = createCache([]);
            ecrRepositoryHasTags.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No ECR repositories present')
            });
        });

        it('should FAIL if repository does not have tags', () => {
            const cache = createCache([describeRepositories[0]], [resourcegroupstaggingapi[1]]);
            ecrRepositoryHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ECR repository does not have any tags')
            })
        });

        it('should PASS if repository has tags', () => {
            const cache = createCache([describeRepositories[0]], [resourcegroupstaggingapi[0]]);
            ecrRepositoryHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ECR repository has tags')
            })
        });

        it('should UNKNOWN if unable to describe ecr resource', () => {
            const cache = repositoryErrorCache();
            ecrRepositoryHasTags.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for ECR repositories')
                
            });
        });
         it('should give unknown result if unable to query resource group tagging api', () => {
            const cache = createCache([describeRepositories[0]],null);
            ecrRepositoryHasTags.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources')
            });
        });
    })
})