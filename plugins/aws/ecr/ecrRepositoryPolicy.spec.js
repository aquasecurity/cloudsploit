var expect = require('chai').expect;
const ecrRepositoryPolicy = require('./ecrRepositoryPolicy');

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
]

const getRepositoryPolicy = [
    {
        "registryId": "111111111111",
        "repositoryName": "test",
        "policyText": "{\n  \"Version\" : \"2008-10-17\",\n  \"Statement\" : [ {\n    \"Sid\" : \"new statement\",\n    \"Effect\" : \"Allow\",\n    \"Principal\" : \"*\",\n    \"Action\" : [ \"ecr:DescribeImages\", \"ecr:PutImage\" ]\n  } ]\n}"
    },
    {
        "registryId": "111111111111",
        "repositoryName": "test",
        "policyText": "{\n  \"Version\" : \"2008-10-17\",\n  \"Statement\" : [ {\n    \"Sid\" : \"new statement\",\n    \"Effect\" : \"Allow\",\n    \"Principal\" : { \"AWS\" : \"arn:aws:iam::111122223333:root\"},\n    \"Action\" : [ \"ecr:DescribeImages\", \"ecr:PutImage\" ]\n  } ]\n}"
    },
    {
        "registryId": "111111111111",
        "repositoryName": "test",
        "policyText": "{\n  \"Version\" : \"2008-10-17\",\n"
    },
    {
        "registryId": "111111111111",
        "repositoryName": "test",
    }
]

const createCache = (ecrRepository, repositoryPolicy) => {
    return {
        ecr: {
            describeRepositories: {
                "us-east-1": {
                    data: ecrRepository
                }
            },
            getRepositoryPolicy: {
                "us-east-1": {
                    "test": {

                        data: repositoryPolicy
                    }
                }
            }
        }
    }

}

const repositoryPolicyErrorCache = (ecrRepository) => {
    return {
        ecr: {
            describeRepositories: {
                "us-east-1": {
                    data: ecrRepository
                }
            },
            getRepositoryPolicy: {
                "us-east-1": {
                    "test": {
                        err: {
                            "message": "Repository policy does not exist for the repository with name 'test' in the registry with id '111111111111'",
                            "code": "RepositoryPolicyNotFoundException",
                            "time": "2021-07-24T12:24:42.602Z",
                            "requestId": "a3aa74d2-c889-419a-98bc-ae91787cddc8",
                            "statusCode": 400,
                            "retryable": false,
                            "retryDelay": 57.277474027512554                        
                        }
                    }
                }
            }
        }
    }
}

describe('ecrRepositoryPolicy', () => {
    describe('run', () => {
        it('should PASS if ecr registry policy does not exist', () => {
            const cache = repositoryPolicyErrorCache([describeRepositories[0]]);
            ecrRepositoryPolicy.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            });
        });

        it('should PASS if custom policy doe snot exist', () => {
            const cache = createCache([describeRepositories[0]], getRepositoryPolicy[2]);
            ecrRepositoryPolicy.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            });
        });

        it('should PASS if no ecr repositories exist', () => {
            const cache = createCache([], getRepositoryPolicy[2]);
            ecrRepositoryPolicy.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            });
        });

        it('should PASS if overly permissive statement does not exist', () => {
            const cache = createCache([describeRepositories[0]],getRepositoryPolicy[1]);
            ecrRepositoryPolicy.run(cache, {ecr_check_cross_account_principal: 'false', ecr_check_global_principal: 'false'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            })
        });

        it('should FAIL if global access allowed', () => {
            const cache = createCache([describeRepositories[0]],getRepositoryPolicy[0]);
            ecrRepositoryPolicy.run(cache, {ecr_check_global_principal: 'true'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            })
        });

        it('should FAIL if cross account access allowed', () => {
            const cache = createCache([describeRepositories[0]],getRepositoryPolicy[1]);
            ecrRepositoryPolicy.run(cache, {ecr_check_cross_account_principal: 'true'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            })
        });

        it('should UNKNOWN if unable to get repository policy', () => {
            const cache = createCache([describeRepositories[0]], getRepositoryPolicy[3]);
            ecrRepositoryPolicy.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
            });
        });
    })
})