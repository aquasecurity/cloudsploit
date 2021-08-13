var expect = require('chai').expect;
const ecrRepositoryTagImmutability = require('./ecrRepositoryTagImmutability');

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

const createCache = (ecrRepository) => {
    return {
        ecr: {
            describeRepositories: {
                "us-east-1": {
                    data: ecrRepository
                }
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

describe('ecrRepositoryTagImmutability', () => {
    describe('run', () => {

        it('should PASS if no ecr repositories exist', () => {
            const cache = createCache([]);
            ecrRepositoryTagImmutability.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            });
        });

        it('should FAIL if repository is mutable', () => {
            const cache = createCache([describeRepositories[0]]);
            ecrRepositoryTagImmutability.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            })
        });

        it('should PASS if repository is immutable', () => {
            const cache = createCache([describeRepositories[1]]);
            ecrRepositoryTagImmutability.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            })
        });

        it('should UNKNOWN if unable to get repository policy', () => {
            const cache = repositoryErrorCache();
            ecrRepositoryTagImmutability.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
            });
        });
    })
})