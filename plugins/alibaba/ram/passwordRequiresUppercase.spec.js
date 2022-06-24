var expect = require('chai').expect;
var passwordRequiresUppercase = require('./passwordRequiresUppercase')

const getPasswordPolicy = [
    {
        MinimumPasswordLength:8,
        RequireLowercaseCharacters:false,
        RequireNumbers:false,
        MaxLoginAttemps:0,
        MaxPasswordAge:0,
        PasswordReusePrevention:0,
        HardExpiry:false,
        RequireUppercaseCharacters:false,
        RequireSymbols:false
    },
    {
        MinimumPasswordLength:8,
        RequireLowercaseCharacters:false,
        RequireNumbers:false,
        MaxLoginAttemps:0,
        MaxPasswordAge:0,
        PasswordReusePrevention:0,
        HardExpiry:false,
        RequireUppercaseCharacters:true,
        RequireSymbols:false
    }
];

const createCache = (data, err) => {
    return {
        ram: {
            GetPasswordPolicy: {
                'cn-hangzhou': {
                    data: data,
                    err: err
                }
            }
        }
    }
}

describe('passwordRequiresUppercase', function () {
    describe('run', function () {
        it('should FAIL if RAM password security policy does not require uppercase characters', function (done) {
            const cache = createCache(getPasswordPolicy[0]);
            passwordRequiresUppercase.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RAM password security policy does not require uppercase characters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RAM password security policy requires uppercase characters', function (done) {
            const cache = createCache(getPasswordPolicy[1]);
            passwordRequiresUppercase.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RAM password security policy requires uppercase characters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RAM password policy', function (done) {
            const cache = createCache({});
            passwordRequiresUppercase.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RAM password policy');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})