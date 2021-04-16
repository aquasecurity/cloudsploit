var parse = function(obj, path) {
    if (typeof path == 'string') path = path.split('.');
    if (Array.isArray(path) && path.length) {
        var localPath = path.shift();
        if (obj[localPath] || typeof obj[localPath] === 'boolean') {
            return parse(obj[localPath], path);
        } else {
            return 'not set';
        }
    } else {
        return obj;
    }
};

var transform = function(val, transformation) {
    if (transformation == 'DATE') {
        return new Date(val);
    } else if (transformation == 'INTEGER') {
        return parseInt(val);
    } else if (transformation == 'STRING') {
        return val.toString();
    } else if (transformation == 'DAYSFROM') {
        // Return the number of days between the date and now
        var now = new Date();
        var then = new Date(val);
        var timeDiff = then.getTime() - now.getTime();
        var diff = Math.round(timeDiff / (1000 * 3600 * 24));
        return diff;
    } else if (transformation == 'COUNT') {
        return val.length;
    } else if (transformation == 'EACH') {
        return val;
    } else if (transformation == 'TOLOWERCASE') {
        return val.toLowerCase();
    } else {
        return val;
    }
};

function evaluateConditions(obj, conditions){
    var preVal = {}; // place to hold the result evaluated till now
    for (let i in conditions){
        let condition = conditions[i];
        let value = validate(obj,condition);

        if (!condition.logical){
            // no logical operation means
            // first element of the conditions
            if ( i == 0){
                // first element in the condition list,so set the preVal
                preVal = value;
            } else {
                // error as no logical condition and not the first element
                //err
                console.error('No logical operator found and this is not the first element');
            }
        } else {
            if ( i == 0){
                // first element in the condition list,and with logical operation. Error case
                console.error('logical operator found in first element');
            } else {
                // this is not first element in array and also logical op is here. use the preVal and evaluate it
                if (preVal){
                    //as this is not first element in array  preVal  should be set.
                    //other wise the condition is not properly formed as AND OR are binary ops
                    if ( condition.logical === 'OR'){
                        preVal.status = preVal.status || value.status;
                    } else if (condition.logical === 'AND'){
                        preVal.status = preVal.status && value.status;
                    } else {
                        // unsupported operator.
                        console.error('wrong logical operator mentioned');
                    }
                    preVal.message = preVal.message.concat(', ',value.message);
                } else {
                    //condition is not properly formed as AND OR are binary ops
                    console.error('condition is malformed');
                }
            }
        }
    }

    return preVal;
}

var validate = function(obj, condition) {
    var result = 0;
    var message = [];
    var override = false;

    // Extract the values for the conditions

    if (condition.property) {
        var conditionResult = 0;
        condition.parsed = parse(obj, condition.property);

        // Transform the property if required
        if (condition.transform) {
            condition.parsed = transform(condition.parsed, condition.transform);
        }

        // Compare the property with the operator
        if (condition.parsed === 'not set'){
            conditionResult = 2;
            message.push(`${condition.property}: not set to any value`);
        } else if (condition.op) {
            if (condition.op == 'EQ') {
                if (condition.parsed == condition.value) {
                    message.push(`${condition.property}: ${condition.parsed} matched: ${condition.value}`);
                } else {
                    conditionResult = 2;
                    message.push(`${condition.property}: ${condition.parsed} did not match: ${condition.value}`);
                }
            } else if (condition.op == 'GT') {
                if (condition.parsed > condition.value) {
                    message.push(`${condition.property}: count of ${condition.parsed} was greater than: ${condition.value}`);
                } else {
                    conditionResult = 2;
                    message.push(`${condition.property}: count of ${condition.parsed} was not greater than: ${condition.value}`);
                }
            } else if (condition.op == 'NE') {
                if (condition.parsed !== condition.value) {
                    message.push(`${condition.property}: ${condition.parsed} is not: ${condition.value}`);
                } else {
                    conditionResult = 2;
                    message.push(`${condition.property}: ${condition.parsed} is: ${condition.value}`);
                }
            } else if (condition.op == 'MATCHES') {
                var userRegex = RegExp(condition.value);
                if (userRegex.test(condition.parsed)) {
                    message.push(`${condition.property}: ${condition.parsed} matches the regex: ${condition.value}`);
                } else {
                    conditionResult = 2;
                    message.push(`${condition.property}: ${condition.parsed} does not match the regex: ${condition.value}`);
                }
            } else if (condition.op == 'EXISTS') {
                if (condition.parsed !== 'not set') {
                    message.push(`${condition.property}: set to ${condition.parsed}`);
                } else {
                    conditionResult = 2;
                    message.push(`${condition.property}: ${condition.parsed}`);
                }
            } else if (condition.op == 'ISTRUE') {
                if (condition.parsed) {
                    message.push(`${condition.property} is true`);
                } else {
                    conditionResult = 2;
                    message.push(`${condition.property} is false`);
                }
            } else if (condition.op == 'ISFALSE') {
                if (!condition.parsed) {
                    message.push(`${condition.property} is false`);
                } else {
                    conditionResult = 2;
                    message.push(`${condition.property} is true`);
                }
            } else if (condition.op == 'CONTAINS') {
                if (condition.parsed.includes(condition.value)) {
                    message.push(`${condition.property}: ${condition.value} found in ${condition.parsed}`);
                } else {
                    conditionResult = 2;
                    message.push(`${condition.value} not found in ${condition.parsed}`);
                }
            }
        } else if (condition.transform && condition.transform == 'EACH' && condition.conditions) {
            // Recurse into the same function
            var subProcessed = [];
            condition.parsed.forEach(function(parsed) {
                subProcessed.push(validate(parsed, condition.conditions));
            });
            subProcessed.forEach(function(sub) {
                if (sub.status) conditionResult = sub.status;
                if (sub.message) message.push(sub.message);
            });
        }
        if (condition.invert) conditionResult = (conditionResult ? 0 : 2);

        if (condition.override && !conditionResult) override = true;
        if (conditionResult) result = conditionResult;
    }


    if (result && override) result = 0;

    if (!message.length) {
        message = ['The resource matched all required conditions'];
    }

    return {
        status: result,
        message: message.join(', ')
    };
};

var asl = function(source, input, resourceMap, callback) {
    if (!source || !input) return callback('No source or input provided');
    if (!input.apis || !input.apis[0]) return callback('No APIs provided for input');
    if (!input.conditions || !input.conditions.length) return callback('No conditions provided for input');

    // Split apis into service:api
    // TODO: support conditions that use different APIs
    var service = input.conditions[0].service;
    var api = input.conditions[0].api;
    var resourcePath;
    if (resourceMap &&
        resourceMap[service] &&
        resourceMap[service][api]) {
        resourcePath = resourceMap[service][api];
    }

    if (!source[service]) return callback(`Source data did not contain service: ${service}`);
    if (!source[service][api]) return callback(`Source data did not contain API: ${api}`);

    var results = [];

    for (var region in source[service][api]) {
        var regionVal = source[service][api][region];
        if (typeof regionVal !== 'object') continue;
        if (regionVal.err) {
            results.push({
                status: 3,
                message: regionVal.err.message || 'Error',
                region: region
            });
        } else if (regionVal.data && regionVal.data.length) {
            // It's an array, loop
            regionVal.data.forEach(function(regionData) {
                var validated = evaluateConditions(regionData, input.conditions);
                var parsedResource = parse(regionData, resourcePath);
                if (typeof parsedResource !== 'string') parsedResource = null;

                results.push({
                    status: validated.status,
                    resource: parsedResource,
                    message: validated.message,
                    region: region
                });
            });
        } else {
            for (var resourceName in regionVal) {
                var resourceObj = regionVal[resourceName];
                if (resourceObj.err) {
                    results.push({
                        status: 3,
                        resource: resourceName,
                        message: resourceObj.err.message || 'Error',
                        region: region
                    });
                } else if (!resourceObj.data) {
                    results.push({
                        status: 3,
                        resource: resourceName,
                        message: 'No data returned',
                        region: region
                    });
                } else {
                    var validated = evaluateConditions(resourceObj.data, input.conditions);
                    var parsedResource = parse(resourceObj.data, resourcePath);
                    if (typeof parsedResource !== 'string') parsedResource = null;

                    results.push({
                        status: validated.status,
                        resource: parsedResource ? parsedResource : resourceName,
                        message: validated.message,
                        region: region
                    });
                }
            }
        }
    }

    callback(null, results, source[service][api]);
};

module.exports = asl;