var expect = require('chai').expect;
const vaultPublicAccess = require('./vaultPublicAccess');

const vaultPolicy = [
    {
        policy: {
            Policy: "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"111111111111\",\"Action\":\"glacier:*\",\"Resource\":\"arn:aws:glacier:us-east-1:111111111111:vaults/vault-access\"}]}",
        },
    },
    {
        policy: {
            Policy: "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"glacier:*\",\"Resource\":\"arn:aws:glacier:us-east-1:111111111111:vaults/vault-access\"}]}",
        },
    },
    {
        policy: {
            Policy: "{\"Version\":\"2012-10-17\",\"Statement\":[]}",
        },
    },
    {
        policy: {
            Policy: '{"Version":"2012-10-17"}'
        },
    },
];

const listVaults = {
    VaultARN: "arn:aws:glacier:us-east-1:111111111111:vaults/vault-access",
    VaultName: "vault-access",
    CreationDate: "2021-09-08T18:07:43.593Z",
    LastInventoryDate: null,
    NumberOfArchives: 0,
    SizeInBytes: 0,
}

const createCache = (vault, policy) => {
    var vaultName = (vault && vault.length && vault[0].VaultName) ? vault[0].VaultName : null;
    return {
        glacier: {
            listVaults: {
                'us-east-1': {
                    data: vault
                },
            },
            getVaultAccessPolicy: {
                'us-east-1': {
                    [vaultName]: {
                        data: policy
                    },
                },
            },
        }
    }
};

const createErrorCache = () => {
    return {
        glacier: {
            listVaults: {
                'us-east-1': {
                    err: {
                        message: 'error while listing vaults'
                    },
                },
            },
            getVaultAccessPolicy: {
                'us-east-1': {
                    ['name']: {
                        err: {
                            message: 'error while getting vault policy'
                        },
                    },
                },
            },
        },
    };
};

const createPolicyErrorCache = (vault) => {
    var vaultName = vault[0].VaultName;
    return {
        glacier: {
            listVaults: {
                'us-east-1': {
                    data: vault
                }
            },
            getVaultAccessPolicy: {
                'us-east-1': {
                    [vaultName]: {
                        err: {
                            message: 'No Policy Exist'
                        }
                    }
                },
            },
        },
    };
};


const createNullCache = () => {
    return {
        glacier: {
            listVaults: {
                'us-east-1': null,
            },
            getVaultAccessPolicy: {
                'us-east-1': null,
            },
        },
    };
};

describe('vaultPublicAccess', function () {
    describe('run', function () {
        it('should PASS if S3 Glacoer vault policy does not allow global access', function (done) {
            const cache = createCache([listVaults], vaultPolicy[0]);
            vaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('S3 Glacoer vault policy does not allow global access');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 Glacoer vault policy allows global access to the actions', function (done) {
            const cache = createCache([listVaults], vaultPolicy[1]);
            vaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include(`S3 Glacoer vault policy allows global access`);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no S3 vaults to check', function (done) {
            const cache = createCache([]);
            vaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('No S3 Glacier vaults found');
                done();
            });
        });

        it('should PASS if vault policy does not contain any statements', function (done) {
            const cache = createCache([listVaults], vaultPolicy[2]);
            vaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('S3 Glacier vault policy does not contain any statements');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list vaults', function (done) {
            const cache = createErrorCache();
            vaultPublicAccess.run(cache, {}, (err, results) => {
                const { message } = cache.glacier.listVaults['us-east-1'].err;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.equal(`Unable to list S3 Glacier vaults: ${message}`);
                done();
            });
        });

        it('should not return any result if s3 list vaults response is not found', function (done) {
            const cache = createNullCache();
            vaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});