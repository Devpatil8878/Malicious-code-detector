import React, { useState, useEffect } from 'react';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

const SUSPICIOUS_FUNCTIONS = [
  'eval',
  'Function',
  'execScript',
  'exec',
  'execFile',
  'spawn',
  'fork',
  'vm.runInNewContext',
  'crypto'
];

const SUSPICIOUS_IMPORTS = [
  'createElement', 
  'appendChild'
];

const CodeAnalyzer = ({ code }) => {
  const [results, setResults] = useState([]);
  const [sandboxResults, setSandboxResults] = useState([]);
  const [reason, setReason] = useState();

  const detectMaliciousCode = async (code) => {
    const suspiciousNodes = [];

    try {
      const response = await fetch('http://localhost:3001/execute', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code }),
      });
      const data = await response.json();
      if (data.result === 'success') {
        setSandboxResults(`Success: ${data.output}`);
      } else {
        setSandboxResults(`Error: ${data.error}`);
        setReason(`Reason: ${data.reason}`)
      }
    } catch (error) {
      setSandboxResults(`Error: ${error.message}`);
    }


    try {
      const ast = acorn.parse(code, { sourceType: 'module', ecmaVersion: 'latest', locations: true });
      walk.simple(ast, {
        CallExpression(node) {
          const functionName = getFunctionName(node);
          if (SUSPICIOUS_FUNCTIONS.includes(functionName)) {
            suspiciousNodes.push({ functionName, line: node.loc.start.line });
          }
        },
        MemberExpression(node) {
          const functionName = getMemberExpressionName(node);
          if (SUSPICIOUS_FUNCTIONS.includes(functionName) || SUSPICIOUS_IMPORTS.includes(functionName)) {
            suspiciousNodes.push({ functionName, line: node.loc.start.line });
          }
        }
      });
    } catch (error) {
      console.error('Parsing error:', error);
    }
    setResults(suspiciousNodes);
  };

  const getFunctionName = (node) => {
    if (node.callee.type === 'Identifier') {
      return node.callee.name;
    } else if (node.callee.type === 'MemberExpression') {
      return getMemberExpressionName(node.callee);
    }
    return null;
  };

  const getMemberExpressionName = (node) => {
    if (node.object.type === 'Identifier' && node.property.type === 'Identifier') {
      return `${node.object.name}.${node.property.name}`;
    }
    return null;
  };

  useEffect(() => {
    detectMaliciousCode(code);
  }, [code]);

  return (
    <div>
      <h2>Code Analysis Results:</h2>
      <div className="">
        {results.length > 0 ? (
          <div>
            <p className="text-red-500 mb-[0rem]">Malicious code detected!</p>
            <ul>
              {results.map((result, index) => (
                <li key={index}>
                  Function: {result.functionName}, Line: {result.line}
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="text-green-600">Code is safe.</p>
        )}
        <br></br>
        Sandbox Results:{sandboxResults}
        <br />
        {reason && reason}
      </div>
    </div>
  );
};

export default CodeAnalyzer;
