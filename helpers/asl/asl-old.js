var parse = function(obj, path, region, cloud, accountId, resourceId) {
    //(Array.isArray(obj)) return [obj];
    if (typeof path == 'string' && path.includes('.')) path = path.split('.');
    if (Array.isArray(path) && path.length && typeof obj === 'object') {
        var localPath = path.shift();
        if (localPath.includes('[*]')){
            localPath = localPath.split('[')[0];
            if (obj[localPath] && obj[localPath].length && obj[localPath].length === 1) {
                if (!path || !path.length) {
                    return [obj[localPath][0], path];
                } else if (path.length === 1){
                    return [obj[localPath],path[0]];
                    //return parse(obj[localPath][0], path[0]);
                }
            }
            if (path.length && path.join('.').includes('[*]')) {
                return parse(obj[localPath], path);
            } else if (!obj[localPath] || !obj[localPath].length) {
                return ['not set'];
            }
            return [obj[localPath], path];
        }
        if (obj[localPath] || typeof obj[localPath] === 'boolean') {
            return parse(obj[localPath], path);
        } else return ['not set'];
    } else if (!Array.isArray(obj) && path && path.length) {
        if (obj[path] || typeof obj[path] === 'boolean') return [obj[path]];
        else {
            if (cloud==='aws' && path.startsWith('arn:aws')) {
                const template_string = path;
                const placeholders = template_string.match(/{([^{}]+)}/g);
                let extracted_values = [];
                if (placeholders) {
                    extracted_values = placeholders.map(placeholder => {
                        const key = placeholder.slice(1, -1);
                        if (key === 'value') return [obj][0];
                        else return obj[key];
                    });
                }
                // Replace other variables
                let converted_string = template_string
                    .replace(/\{region\}/g, region)
                    .replace(/\{cloudAccount\}/g, accountId)
                    .replace(/\{resourceId\}/g, resourceId);
                placeholders.forEach((placeholder, index) => {
                    if (index === placeholders.length - 1) {
                        converted_string = converted_string.replace(placeholder, extracted_values.pop());
                    } else {
                        converted_string = converted_string.replace(placeholder, extracted_values.shift());
                    }
                });
                path = converted_string;
                return [path];
            } else return ['not set'];
        }
    } else if (Array.isArray(obj)) {
        return [obj];
    } else {
        return [obj];
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
        var diff = (Math.round(timeDiff / (1000 * 3600 * 24)));
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

var compositeResult = function(inputResultsArr, resource, region, results, logical) {
    let failingResults = [];
    let passingResults = [];
    
    // No results to process, exit early
    if (!inputResultsArr || !inputResultsArr.length) {
        results.push({
            status: 2,
            resource: resource,
            message: 'No results to evaluate',
            region: region
        });
        return;
    }
    
    inputResultsArr.forEach(localResult => {
        if (localResult.status === 2) {
            failingResults.push(localResult.message);
        }

        if (localResult.status === 0) {
            passingResults.push(localResult.message);
        }
    });

    if (!logical) {
        results.push({
            status: inputResultsArr[0].status,
            resource: resource,
            message: inputResultsArr[0].message,
            region: region
        });
    } else if (logical === 'AND') {
        if (failingResults && failingResults.length) {
            results.push({
                status: 2,
                resource: resource,
                message: failingResults.join(' and '),
                region: region
            });
        } else {
            results.push({
                status: 0,
                resource: resource,
                message: passingResults.join(' and '),
                region: region
            });
        }
    } else {
        if (passingResults && passingResults.length) {
            results.push({
                status: 0,
                resource: resource,
                message: passingResults.join(' and '),
                region: region
            });
        } else {
            results.push({
                status: 2,
                resource: resource,
                message: failingResults.join(' and '),
                region: region
            });
        }
    }
};

var validate = function(condition, conditionResult, inputResultsArr, message, property, parsed) {
    if (Array.isArray(property)){
        property = property[property.length-1];
    }
    
    // Special case for AliasTarget properties
    if (property && property.includes('AliasTarget') && parsed && typeof parsed === 'object') {
        // Handle the AliasTarget object which has HostedZoneId, DNSName, and EvaluateTargetHealth
        if (condition.property && condition.property.includes('AliasTarget')) {
            // Extract the specific AliasTarget sub-property if specified
            const aliasProperty = condition.property.split('.')[1]; // Get the part after AliasTarget.
            if (aliasProperty && parsed.AliasTarget && parsed.AliasTarget[aliasProperty]) {
                condition.parsed = parsed.AliasTarget[aliasProperty];
            } else if (!aliasProperty && parsed.AliasTarget) {
                condition.parsed = parsed.AliasTarget;
            }
        }
    } else if (parsed && typeof parsed === 'object' && parsed[property]) {
        condition.parsed = parsed[property];
    }

    if (condition.transform) {
        try {
            condition.parsed = transform(condition.parsed, condition.transform);
        } catch (e) {
            conditionResult = 2;
            message.push(`${property}: unable to perform transformation`);
            let resultObj = {
                status: conditionResult,
                message: message.join(', ')
            };

            inputResultsArr.push(resultObj);
            return resultObj;
        }
    }

    // Compare the property with the operator
    if (condition.op) {
        let userRegex;
        if (condition.op === 'MATCHES' || condition.op === 'NOTMATCHES') {
            userRegex = new RegExp(condition.value);
        }
        if (condition.transform && condition.transform == 'EACH' && condition) {
            if (condition.op == 'CONTAINS') {
                var stringifiedCondition = JSON.stringify(condition.parsed);
                if (condition.value && condition.value.includes(':')) {
                    var key = condition.value.split(/:(?!.*:)/)[0];
                    var value = condition.value.split(/:(?!.*:)/)[1];

                    if (stringifiedCondition.includes(key) && stringifiedCondition.includes(value)){
                        message.push(`${property}: ${condition.value} found in ${stringifiedCondition}`);
                        return 0;
                    } else {
                        message.push(`${condition.value} not found in ${stringifiedCondition}`);
                        return 2;
                    }
                } else if (stringifiedCondition && stringifiedCondition.includes(condition.value)) {
                    message.push(`${property}: ${condition.value} found in ${stringifiedCondition}`);
                    return 0;
                } else if (stringifiedCondition && stringifiedCondition.length){
                    message.push(`${condition.value} not found in ${stringifiedCondition}`);
                    return 2;
                } else {
                    message.push(`${condition.parsed} is not the right property type for this operation`);
                    return 2;
                }
            } else if (condition.op == 'NOTCONTAINS') {
                var conditionStringified = JSON.stringify(condition.parsed);
                if (condition.value && condition.value.includes(':')) {

                    var conditionKey = condition.value.split(/:(?!.*:)/)[0];
                    var conditionValue = condition.value.split(/:(?!.*:)/)[1];

                    if (conditionStringified.includes(conditionKey) && !conditionStringified.includes(conditionValue)){
                        message.push(`${property}: ${condition.value} not found in ${conditionStringified}`);
                        return 0;
                    } else {
                        message.push(`${condition.value} found in ${conditionStringified}`);
                        return 2;
                    }
                } else if (conditionStringified && !conditionStringified.includes(condition.value)) {
                    message.push(`${property}: ${condition.value} not found in ${conditionStringified}`);
                    return 0;
                } else if (conditionStringified && conditionStringified.length){
                    message.push(`${condition.value} found in ${conditionStringified}`);
                    return 2;
                } else {
                    message.push(`${condition.parsed} is not the right property type for this operation`);
                    return 2;
                }
            } else {
                // Recurse into the same function
                var subProcessed = [];
                if (!condition.parsed.length) {
                    conditionResult = 2;
                    message.push(`${property}: is not iterable using EACH transformation`);
                }  else {
                    condition.parsed.forEach(function(parsed) {
                        subProcessed.push(runValidation(parsed, condition, inputResultsArr));
                    });
                    subProcessed.forEach(function(sub) {
                        if (sub.status) conditionResult = sub.status;
                        if (sub.message) message.push(sub.message);
                    });
                }
            }
        } else if (condition.op == 'EQ') {
            if (condition.parsed == condition.value) {
                message.push(`${property}: ${condition.parsed} matched: ${condition.value}`);
                return 0;
            } else {
                message.push(`${property}: ${condition.parsed} did not match: ${condition.value}`);
                return 2;
            }
        } else if (condition.op == 'GT') {
            // Convert to numbers for comparison if they are numeric strings
            let parsedVal = condition.parsed;
            let comparisonVal = condition.value;
            
            // Force numeric conversion
            parsedVal = Number(parsedVal);
            comparisonVal = Number(comparisonVal);
            
            if (parsedVal > comparisonVal) {
                message.push(`${property}: count of ${condition.parsed} was greater than: ${condition.value}`);
                return 0;
            } else {
                conditionResult = 2;
                message.push(`${property}: count of ${condition.parsed} was not greater than: ${condition.value}`);
                return 2;
            }
        } else if (condition.op == 'LT') {
            // Convert to numbers for comparison if they are numeric strings
            let parsedVal = condition.parsed;
            let comparisonVal = condition.value;
            
            // Force numeric conversion
            parsedVal = Number(parsedVal);
            comparisonVal = Number(comparisonVal);
            
            if (parsedVal < comparisonVal) {
                message.push(`${property}: count of ${condition.parsed} was less than: ${condition.value}`);
                return 0;
            } else {
                conditionResult = 2;
                message.push(`${property}: count of ${condition.parsed} was not less than: ${condition.value}`);
                return 2;
            }
        } else if (condition.op == 'NE') {
            if (condition.parsed !== condition.value) {
                message.push(`${property}: ${condition.parsed} is not: ${condition.value}`);
                return 0;
            } else {
                conditionResult = 2;
                message.push(`${property}: ${condition.parsed} is: ${condition.value}`);
                return 2;
            }
        } else if (condition.op == 'MATCHES') {
            if (userRegex.test(condition.parsed)) {
                message.push(`${property}: ${condition.parsed} matches the regex: ${condition.value}`);
                return 0;
            } else {
                conditionResult = 2;
                message.push(`${property}: ${condition.parsed} does not match the regex: ${condition.value}`);
                return 2;
            }
        } else if (condition.op == 'NOTMATCHES') {
            if (!userRegex.test(condition.parsed)) {
                message.push(`${condition.property}: ${condition.parsed} does not match the regex: ${condition.value}`);
                return 0;
            } else {
                conditionResult = 2;
                message.push(`${condition.property}: ${condition.parsed} matches the regex : ${condition.value}`);
                return 2;
            }
        } else if (condition.op == 'EXISTS') {
            if (condition.parsed !== 'not set') {
                message.push(`${property}: set to ${condition.parsed}`);
                return 0;
            } else {
                message.push(`${property}: ${condition.parsed}`);
                return 2;
            }
        } else if (condition.op == 'ISTRUE') {
            if (typeof condition.parsed == 'boolean' && condition.parsed) {
                message.push(`${property} is true`);
                return 0;
            } else if (typeof condition.parsed == 'boolean' && !condition.parsed) {
                conditionResult = 2;
                message.push(`${property} is false`);
                return 2;
            } else {
                message.push(`${property} is not a boolean value`);
                return 2;
            }
        } else if (condition.op == 'ISFALSE') {
            if (typeof condition.parsed == 'boolean' && !condition.parsed) {
                message.push(`${property} is false`);
                return 0;
            } else if (typeof condition.parsed == 'boolean' && condition.parsed) {
                conditionResult = 2;
                message.push(`${property} is true`);
                return 2;
            } else {
                message.push(`${property} is not a boolean value`);
                return 2;
            }
        } else if (condition.op == 'CONTAINS') {
            if (condition.parsed && condition.parsed.length && condition.parsed.includes(condition.value)) {
                message.push(`${property}: ${condition.value} found in ${condition.parsed}`);
                return 0;
            } else if (condition.parsed && condition.parsed.length){
                message.push(`${condition.value} not found in ${condition.parsed}`);
                return 2;
            } else {
                message.push(`${condition.parsed} is not the right property type for this operation`);
                return 2;
            }
        } else if (condition.op == 'NOTCONTAINS') {
            if (condition.parsed && condition.parsed.length && !condition.parsed.includes(condition.value)) {
                message.push(`${property}: ${condition.value} not found in ${condition.parsed}`);
                return 0;
            } else if (condition.parsed && condition.parsed.length){
                message.push(`${condition.value} found in ${condition.parsed}`);
                return 2;
            } else {
                message.push(`${condition.parsed} is not the right property type for this operation`);
                return 2;
            }
        }
        return conditionResult;
    }
};

var runValidation = function(obj, condition, inputResultsArr, nestedResultArr) {
    let result = 0;
    let message = [];

    // Extract the values for the conditions
    if (condition.property) {

        let conditionResult = 0;
        let property;
        if (Array.isArray(condition.property)) {
            if (condition.property.length === 1) {
                property = condition.property[0];
            } else if (condition.property.length > 1) {
                property = condition.property.slice(0);
            }
        } else {
            property = condition.property;
        }
        
        // Handle AliasTarget special cases
        let isAliasTargetProperty = false;
        if (typeof property === 'string' && property.includes('AliasTarget')) {
            isAliasTargetProperty = true;
            const propertyParts = property.split('.');
            const aliasProperty = propertyParts.length > 1 ? propertyParts[1] : null;
            
            if (obj && obj.AliasTarget) {
                if (aliasProperty && obj.AliasTarget[aliasProperty] !== undefined) {
                    condition.parsed = obj.AliasTarget[aliasProperty];
                } else if (!aliasProperty) {
                    condition.parsed = obj.AliasTarget;
                } else {
                    condition.parsed = 'not set';
                }
            } else {
                condition.parsed = 'not set';
            }
        } else {
            condition.parsed = parse(obj, condition.property)[0];
        }

        if ((typeof condition.parsed !== 'boolean' && !condition.parsed) || condition.parsed === 'not set'){
            conditionResult = 2;
            message.push(`${property}: not set to any value`);

            let resultObj = {
                status: conditionResult,
                message: message.join(', ')
            };

            inputResultsArr.push(resultObj);
            return resultObj;
        }

        if (property.includes('[*]') && !isAliasTargetProperty) {
            if (Array.isArray(condition.parsed)) {
                if (!Array.isArray(nestedResultArr)) nestedResultArr = [];
                let propertyArr = property.split('.');
                propertyArr.shift();
                property = propertyArr.join('.');
                condition.property = property;
                if (condition.op !== 'CONTAINS' || condition.op !== 'NOTCONTAINS') {
                    condition.parsed.forEach(parsed => {
                        if (property.includes('[*]')) {
                            runValidation(parsed, condition, inputResultsArr, nestedResultArr);
                        } else {
                            let localConditionResult = validate(condition, conditionResult, inputResultsArr, message, property, parsed);
                            nestedResultArr.push(localConditionResult);
                        }
                    });
                } else {
                    runValidation(condition.parsed, condition, inputResultsArr, nestedResultArr);
                }
                // NestedCompositeResult
                if (nestedResultArr && nestedResultArr.length) {
                    if (!condition.nested) condition.nested = 'ONE';
                    let resultObj;
                    if ((condition.nested.toUpperCase() === 'ONE' && nestedResultArr.indexOf(0) > -1) || (condition.nested.toUpperCase() === 'ALL' && nestedResultArr.indexOf(2) === 0)) {
                        resultObj = {
                            status: 0,
                            message: message.join(', ')
                        };
                    } else {
                        resultObj = {
                            status: 2,
                            message: message.join(', ')
                        };
                    }

                    inputResultsArr.push(resultObj);
                    return resultObj;
                }
            } else {
                if (!Array.isArray(nestedResultArr)) nestedResultArr = [];
                let propertyArr = property.split('.');
                propertyArr.shift();
                property = propertyArr.join('.');
                let localConditionResult = validate(condition, conditionResult, inputResultsArr, message, condition.property, condition.parsed);

                let resultObj = {
                    status: localConditionResult,
                    message: message.join(', ')
                };

                inputResultsArr.push(resultObj);
                return resultObj;
            }
        } else {
            // Transform the property if required
            conditionResult = validate(condition, conditionResult, inputResultsArr, message, property, obj);
            if (conditionResult) result = conditionResult;
        }
    }

    if (!message.length) {
        message = ['The resource matched all required conditions'];
    }

    let resultObj = {
        status: result,
        message: message.join(', ')
    };

    inputResultsArr.push(resultObj);
    return resultObj;
};

var runConditions = function(input, data, results, resourcePath, resourceName, region, cloud, accountId) {
    let dataToValidate;
    let newPath;
    let newData;
    let validated;
    let parsedResource = resourceName;

    let inputResultsArr = [];
    let logical;
    let localInput = JSON.parse(JSON.stringify(input));

    // to check if top level * matches. ex: Instances[*] should be
    // present in each condition if not its impossible to compare resources
    let resourceConditionArr = [];
    
    localInput.conditions.forEach(condition => {
        logical = condition.logical;
        var conditionPropArr = condition.property.split('.');
        
        // Special handling for ResourceRecordSets[*].AliasTarget.* properties
        if (condition.property && condition.property.includes('ResourceRecordSets[*].AliasTarget')) {
            let foundMatch = false;
            let matchResults = [];
            let nonMatchResults = [];
            
            if (data && data.ResourceRecordSets && Array.isArray(data.ResourceRecordSets)) {
                // Directly access ResourceRecordSets if it exists at the top level
                for (let i = 0; i < data.ResourceRecordSets.length; i++) {
                    let record = data.ResourceRecordSets[i];
                    if (record && record.AliasTarget) {
                        // Extract just the AliasTarget part of the property path
                        const aliasProperty = condition.property.split('AliasTarget.')[1];
                        
                        if (aliasProperty && record.AliasTarget[aliasProperty]) {
                            let propValue = record.AliasTarget[aliasProperty];
                            let result = 2; // Default to fail
                            let message = '';
                            
                            // Perform the actual comparison
                            if (condition.op === 'CONTAINS' && propValue.includes(condition.value)) {
                                result = 0;
                                message = `${aliasProperty}: ${condition.value} found in ${propValue}`;
                                foundMatch = true;
                                matchResults.push({
                                    status: result,
                                    message: message,
                                    resource: record.Name || resourceName
                                });
                            } else if (condition.op === 'NOTCONTAINS' && !propValue.includes(condition.value)) {
                                result = 0;
                                message = `${aliasProperty}: ${condition.value} not found in ${propValue}`;
                                foundMatch = true;
                                matchResults.push({
                                    status: result,
                                    message: message,
                                    resource: record.Name || resourceName
                                });
                            } else if (condition.op === 'EQ' && propValue === condition.value) {
                                result = 0;
                                message = `${aliasProperty}: ${propValue} matched: ${condition.value}`;
                                foundMatch = true;
                                matchResults.push({
                                    status: result,
                                    message: message,
                                    resource: record.Name || resourceName
                                });
                            } else if (condition.op === 'NE' && propValue !== condition.value) {
                                result = 0;
                                message = `${aliasProperty}: ${propValue} is not: ${condition.value}`;
                                foundMatch = true;
                                matchResults.push({
                                    status: result,
                                    message: message,
                                    resource: record.Name || resourceName
                                });
                            } else if (condition.op === 'GT') {
                                // Convert to numbers for comparison if they are numeric strings
                                let parsedVal = Number(propValue);
                                let comparisonVal = Number(condition.value);
                                
                                if (!isNaN(parsedVal) && !isNaN(comparisonVal) && parsedVal > comparisonVal) {
                                    result = 0;
                                    message = `${aliasProperty}: ${propValue} was greater than: ${condition.value}`;
                                    foundMatch = true;
                                    matchResults.push({
                                        status: result,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                } else {
                                    message = `${aliasProperty}: ${propValue} was not greater than: ${condition.value}`;
                                    nonMatchResults.push({
                                        status: 2,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                }
                            } else if (condition.op === 'LT') {
                                // Convert to numbers for comparison if they are numeric strings
                                let parsedVal = Number(propValue);
                                let comparisonVal = Number(condition.value);
                                
                                if (!isNaN(parsedVal) && !isNaN(comparisonVal) && parsedVal < comparisonVal) {
                                    result = 0;
                                    message = `${aliasProperty}: ${propValue} was less than: ${condition.value}`;
                                    foundMatch = true;
                                    matchResults.push({
                                        status: result,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                } else {
                                    message = `${aliasProperty}: ${propValue} was not less than: ${condition.value}`;
                                    nonMatchResults.push({
                                        status: 2,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                }
                            } else if (condition.op === 'ISTRUE') {
                                if (typeof propValue === 'boolean' && propValue === true) {
                                    result = 0;
                                    message = `${aliasProperty} is true`;
                                    foundMatch = true;
                                    matchResults.push({
                                        status: result,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                } else if (typeof propValue === 'string' && 
                                          (propValue.toLowerCase() === 'true' || propValue === '1')) {
                                    result = 0;
                                    message = `${aliasProperty} is true (${propValue})`;
                                    foundMatch = true;
                                    matchResults.push({
                                        status: result,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                } else {
                                    message = `${aliasProperty} is not true`;
                                    nonMatchResults.push({
                                        status: 2,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                }
                            } else if (condition.op === 'ISFALSE') {
                                if (typeof propValue === 'boolean' && propValue === false) {
                                    result = 0;
                                    message = `${aliasProperty} is false`;
                                    foundMatch = true;
                                    matchResults.push({
                                        status: result,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                } else if (typeof propValue === 'string' && 
                                          (propValue.toLowerCase() === 'false' || propValue === '0')) {
                                    result = 0;
                                    message = `${aliasProperty} is false (${propValue})`;
                                    foundMatch = true;
                                    matchResults.push({
                                        status: result,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                } else {
                                    message = `${aliasProperty} is not false`;
                                    nonMatchResults.push({
                                        status: 2,
                                        message: message,
                                        resource: record.Name || resourceName
                                    });
                                }
                            } else if (condition.op === 'EXISTS') {
                                result = 0;
                                message = `${aliasProperty}: set to ${propValue}`;
                                foundMatch = true;
                                matchResults.push({
                                    status: result,
                                    message: message,
                                    resource: record.Name || resourceName
                                });
                            } else if (condition.op === 'MATCHES' && new RegExp(condition.value).test(propValue)) {
                                result = 0;
                                message = `${aliasProperty}: ${propValue} matches the regex: ${condition.value}`;
                                foundMatch = true;
                                matchResults.push({
                                    status: result,
                                    message: message,
                                    resource: record.Name || resourceName
                                });
                            } else if (condition.op === 'NOTMATCHES' && !new RegExp(condition.value).test(propValue)) {
                                result = 0;
                                message = `${aliasProperty}: ${propValue} does not match the regex: ${condition.value}`;
                                foundMatch = true;
                                matchResults.push({
                                    status: result,
                                    message: message,
                                    resource: record.Name || resourceName
                                });
                            } else {
                                if (condition.op === 'CONTAINS') {
                                    message = `${condition.value} not found in ${propValue}`;
                                } else if (condition.op === 'NOTCONTAINS') {
                                    message = `${condition.value} found in ${propValue}`;
                                } else if (condition.op === 'EQ') {
                                    message = `${aliasProperty}: ${propValue} did not match: ${condition.value}`;
                                } else if (condition.op === 'NE') {
                                    message = `${aliasProperty}: ${propValue} is: ${condition.value}`;
                                } else if (condition.op === 'GT') {
                                    message = `${aliasProperty}: ${propValue} was not greater than: ${condition.value}`;
                                } else if (condition.op === 'LT') {
                                    message = `${aliasProperty}: ${propValue} was not less than: ${condition.value}`;
                                } else if (condition.op === 'ISTRUE') {
                                    message = `${aliasProperty} is not true`;
                                } else if (condition.op === 'ISFALSE') {
                                    message = `${aliasProperty} is not false`;
                                } else if (condition.op === 'MATCHES') {
                                    message = `${aliasProperty}: ${propValue} does not match the regex: ${condition.value}`;
                                } else if (condition.op === 'NOTMATCHES') {
                                    message = `${aliasProperty}: ${propValue} matches the regex: ${condition.value}`;
                                }
                                
                                nonMatchResults.push({
                                    status: 2,
                                    message: message,
                                    resource: record.Name || resourceName
                                });
                            }
                        } else if (!aliasProperty) {
                            // Handle the entire AliasTarget object
                            matchResults.push({
                                status: 0,
                                message: `AliasTarget: exists for record ${record.Name}`,
                                resource: record.Name || resourceName
                            });
                            foundMatch = true;
                        }
                    }
                }
            }
            
            // After checking all records, add the appropriate results to inputResultsArr
            if (foundMatch) {
                // If any record matched, add all matching results
                matchResults.forEach(result => {
                    inputResultsArr.push({
                        status: result.status,
                        message: result.message
                    });
                    parsedResource = result.resource;
                });
            } else {
                // If no records matched, add a failure result
                if (nonMatchResults.length > 0) {
                    // Use the first non-matching result as the representative failure
                    inputResultsArr.push({
                        status: 2,
                        message: nonMatchResults[0].message
                    });
                    parsedResource = nonMatchResults[0].resource;
                } else {
                    // No records with AliasTarget found
                    inputResultsArr.push({
                        status: 2,
                        message: `No matching records with AliasTarget.${condition.property.split('AliasTarget.')[1] || ''} found`
                    });
                }
            }
        } else if (condition.property && condition.property.includes('[*]')) {
            if (conditionPropArr.length > 1 && conditionPropArr[1].includes('[*]')) {
                resourceConditionArr.push(conditionPropArr[0]);
                var firstProperty = conditionPropArr.shift();
                dataToValidate = parse(data, firstProperty.split('[*]')[0])[0];
                condition.property = conditionPropArr.join('.');
                if (dataToValidate && dataToValidate.length) {
                    dataToValidate.forEach(newData => {
                        condition.validated = runValidation(newData, condition, inputResultsArr);
                        parsedResource = parse(newData, resourcePath, region, cloud, accountId, resourceName)[0];
                        if (typeof parsedResource !== 'string' || parsedResource === 'not set') parsedResource = resourceName;
                    });
                } else {
                    condition.validated = runValidation([], condition, inputResultsArr);
                    parsedResource = parse([], resourcePath, region, cloud, accountId, resourceName)[0];
                    if (typeof parsedResource !== 'string' || parsedResource === 'not set') parsedResource = resourceName;
                }
                // result per resource
            } else {
                dataToValidate = parse(data, condition.property);
                newPath = dataToValidate[1];
                newData = dataToValidate[0];
                if (newPath && newData && newData.length){
                    newData.forEach(dataElm =>{
                        if (newPath) condition.property = JSON.parse(JSON.stringify(newPath));
                        condition.validated = runValidation(dataElm, condition, inputResultsArr);
                        // Use the Name property as resource if available (common in Route53)
                        parsedResource = dataElm.Name || parse(dataElm, resourcePath, region, cloud, accountId, resourceName)[0];
                        if (typeof parsedResource !== 'string' || parsedResource === 'not set') parsedResource = resourceName;
                    });
                } else if (newPath && !newData.length) {
                    condition.property = JSON.parse(JSON.stringify(newPath));
                    condition.validated = runValidation(newData, condition, inputResultsArr);
                    parsedResource = parse(newData, resourcePath,  region, cloud, accountId, resourceName)[0];
                    if (parsedResource === 'not set' || typeof parsedResource !== 'string') parsedResource = resourceName;
                } else if (!newPath) {
                    // no path returned. means it has fully parsed and got the value.
                    // save the value
                    newPath = JSON.parse(JSON.stringify(condition.property));
                    if (condition.property.includes('.')){
                        condition.property = condition.property.split('.')[condition.property.split('.').length -1 ];
                    }
                    condition.validated = runValidation(newData, condition, inputResultsArr);
                    condition.property = JSON.parse(JSON.stringify(newPath));
                    parsedResource = parse(newData, resourcePath, region, cloud, accountId, resourceName)[0];
                    if (parsedResource === 'not set' || typeof parsedResource !== 'string') parsedResource = resourceName;
                }
            }
        } else {
            dataToValidate = parse(data, condition.property);
            if (dataToValidate.length === 1) {
                validated = runValidation(data, condition, inputResultsArr);
                parsedResource = parse(data, resourcePath, region, cloud, accountId, resourceName)[0];
                if (typeof parsedResource !== 'string' || parsedResource === 'not set') parsedResource = resourceName;
            } else {
                newPath = dataToValidate[1];
                newData = dataToValidate[0];
                condition.property = newPath;
                newData.forEach(element =>{
                    condition.validated = runValidation(element, condition, inputResultsArr);
                    parsedResource = parse(data, resourcePath, region, cloud, accountId, resourceName)[0];
                    if (typeof parsedResource !== 'string' || parsedResource === 'not set') parsedResource = null;

                    results.push({
                        status: validated.status,
                        resource: parsedResource ? parsedResource : resourceName,
                        message: validated.message,
                        region: region
                    });
                });
            }
        }
    });

    compositeResult(inputResultsArr, parsedResource, region, results, logical);
};

var asl = function(source, input, resourceMap, cloud, accountId, callback) {
    if (!source || !input) return callback('No source or input provided');
    if (!input.apis || !input.apis[0]) return callback('No APIs provided for input');
    if (!input.conditions || !input.conditions.length) return callback('No conditions provided for input');
    let service = input.conditions[0].service;
    var subService = (input.conditions[0].subservice) ? input.conditions[0].subservice : null;
    let api = input.conditions[0].api;
    let resourcePath;
    if (resourceMap &&
        resourceMap[service] &&
        resourceMap[service][api]) {
        resourcePath = resourceMap[service][api];
    }

    if (!source[service]) return callback(`Source data did not contain service: ${service}`);
    if (subService && !source[service][subService]) return callback(`Source data did not contain service: ${service}:${subService}`);
    if (subService && !source[service][subService][api]) return callback(`Source data did not contain API: ${api}`);
    if (!subService && !source[service][api]) return callback(`Source data did not contain API: ${api}`);

    var results = [];
    let data = subService ? source[service][subService][api] : source[service][api];

    for (let region in data) {
        let regionVal = data[region];
        if (typeof regionVal !== 'object') continue;
        if (regionVal.err) {
            results.push({
                status: 3,
                message: regionVal.err.message || 'Error',
                region: region
            });
        } else if (regionVal.data && regionVal.data.length) {
            regionVal.data.forEach(function(regionData) {
                var resourceName = parse(regionData, resourcePath, region, cloud, accountId)[0];
                runConditions(input, regionData, results, resourcePath, resourceName, region, cloud, accountId);
            });
        } else if (regionVal.data && Object.keys(regionVal.data).length) {
            runConditions(input, regionVal.data, results, resourcePath, '', region, cloud, accountId);
        } else {
            if (!Object.keys(regionVal).length || (regionVal.data && (!regionVal.data.length || !Object.keys(regionVal.data).length))) {
                results.push({
                    status: 0,
                    message: 'No resources found in this region',
                    region: region
                });
            } else {
                for (let resourceName in regionVal) {
                    let resourceObj = regionVal[resourceName];
                    if (resourceObj.err || !resourceObj.data) {
                        results.push({
                            status: 3,
                            resource: resourceName,
                            message: resourceObj.err.message || 'Error',
                            region: region
                        });
                    } else {
                        if (resourceObj.data && resourceObj.data.length){
                            resourceObj.data.forEach(function(regionData) {
                                var resourceName = parse(regionData, resourcePath, region, cloud, accountId)[0];
                                runConditions(input, regionData, results, resourcePath, resourceName, region, cloud, accountId);
                            });
                        } else {
                            runConditions(input, resourceObj.data, results, resourcePath, resourceName, region, cloud, accountId);
                        }
                    }
                }
            }
        }
    }

    callback(null, results, data);
};

module.exports = asl;
