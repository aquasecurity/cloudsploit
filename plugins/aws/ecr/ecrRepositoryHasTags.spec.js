var expect = require('chai').expect;
const ecrRepositoryHasTags = require('./ecrRepositoryHasTags');

const listTagsForResource = [
    { tags: []},
    { tags: [{key: 'value'}]},
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

const createCache = (ecrRepository, tagsResource) => {
     var repoARN = (ecrRepository && ecrRepository.length) ? ecrRepository[0].repositoryArn : null;
    return {
        ecr: {
            describeRepositories: {
                "us-east-1": {
                    data: ecrRepository
                }
            },
            listTagsForResource: {
                'us-east-1': {
                    [repoARN]: {
                        data: tagsResource
                    },
                },
            }
        }
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
            const cache = createCache([describeRepositories[0]], listTagsForResource[0]);
            ecrRepositoryHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ECR repositories does not have tags')
            })
        });

        it('should PASS if repository has tags', () => {
            const cache = createCache([describeRepositories[0]], listTagsForResource[1]);
            ecrRepositoryHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ECR repositories has tags')
            })
        });

        it('should UNKNOWN if unable to describe repository', () => {
            const cache = repositoryErrorCache();
            ecrRepositoryHasTags.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for ECR repositories')
                
            });
        });
         it('should UNKNOWN if unable to list tags for given resource', () => {
            const cache = createCache([describeRepositories[0]],null);
            ecrRepositoryHasTags.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list tags for resources')
            });
        });
    })
})