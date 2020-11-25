var expect = require('chai').expect;
const passwordRequiresNumbers = require('./passwordRequiresNumbers');

const getAccountPasswordPolicy = [
    {
        "MinimumPasswordLength": 8,
        "RequireSymbols": true,
        "RequireNumbers": true,
        "RequireUppercaseCharacters": true,
        "RequireLowercaseCharacters": true,
        "AllowUsersToChangePassword": true,
        "ExpirePasswords": true,
        "MaxPasswordAge": 80
    },
    {
        "MinimumPasswordLength": 8,
        "RequireSymbols": false,
        "RequireNumbers": false,
        "RequireUppercaseCharacters": false,
        "RequireLowercaseCharacters": false,
        "AllowUsersToChangePassword": false,
        "ExpirePasswords": true,
        "MaxPasswordAge": 120
    }
];

const createCache = (report) => {
    return {
        iam:{
            getAccountPasswordPolicy: {
                'us-east-1': {
                    data: report
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        iam:{
            getAccountPasswordPolicy: {
                'us-east-1': {
                    err: {
                        message: 'error generating credential report'
                    },
                },
            }
        },
    };
};

const createErrorCodeCache = () => {
    return {
        iam:{
            getAccountPasswordPolicy: {
                'us-east-1': {
                    err: {
                        code: 'NoSuchEntity',
                        message: 'error generating credential report'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        iam:{
            getAccountPasswordPolicy: {
                'us-east-1': null,
            },
        },
    };
};

describe('passwordRequiresNumbers', function () {
    describe('run', function () {
        it('should PASS if password policy requires numbers', function (done) {
            const cache = createCache(getAccountPasswordPolicy[0]);
            passwordRequiresNumbers.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if password policy does not require numbers', function (done) {
            const cache = createCache(getAccountPasswordPolicy[1]);
            passwordRequiresNumbers.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if account does not have a password policy', function (done) {
            const cache = createErrorCodeCache();
            passwordRequiresNumbers.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to get account password policy', function (done) {
            const cache = createErrorCache();
            passwordRequiresNumbers.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get account password policy response not found', function (done) {
            const cache = createNullCache();
            passwordRequiresNumbers.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
