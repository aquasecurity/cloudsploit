var expect = require('chai').expect;
var passwordNoReuse = require('./passwordNoReuse')

const getPasswordPolicy = [
    {
        MinimumPasswordLength:8,
        RequireLowercaseCharacters:false,
        RequireNumbers:false,
        MaxLoginAttemps:0,
        MaxPasswordAge:0,
        PasswordReusePrevention:5,
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

describe('passwordNoReuse', function () {
    describe('run', function () {
        it('should FAIL if RAM password security policy does not requires to prevent reusing 5 previous passwords', function (done) {
            const cache = createCache(getPasswordPolicy[1]);
            passwordNoReuse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RAM password security policy does not require to prevent reusing previous 5 passwords');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RAM password security policy requires to prevent reusing 5 previous passwords', function (done) {
            const cache = createCache(getPasswordPolicy[0]);
            passwordNoReuse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RAM password security policy requires to prevent reusing previous 5 or more passwords');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query RAM password policy', function (done) {
            const cache = createCache({});
            passwordNoReuse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RAM password policy');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})