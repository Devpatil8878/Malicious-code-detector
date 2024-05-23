const express = require('express');
const { NodeVM } = require('vm2');
const cors = require('cors');
const esprima = require('esprima');
const estraverse = require('estraverse');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello, World!');
});

function analyzeCodeForMaliciousPatterns(code) {
  try {
    const ast = esprima.parseScript(code);
    let isMalicious = false;
    let maliciousReason = '';

    estraverse.traverse(ast, {
      enter(node) {
        if (node.type === 'CallExpression' && node.callee.name === 'eval') {
          isMalicious = true;
          maliciousReason = 'Use of eval detected';
        } else if (
          node.type === 'BinaryExpression' &&
          node.operator === '^'
        ) {
          isMalicious = true;
          maliciousReason = 'Potential XOR decryption detected';
        } else if (
          node.type === 'NewExpression' &&
          node.callee.name === 'ActiveXObject'
        ) {
          isMalicious = true;
          maliciousReason = 'Use of ActiveXObject detected';
        }
      }
    });

    return { isMalicious, maliciousReason };
  } catch (e) {
    return { isMalicious: true, maliciousReason: 'Code parsing error' };
  }
}

app.post('/execute', (req, res) => {
  const { code } = req.body;

  const { isMalicious, maliciousReason } = analyzeCodeForMaliciousPatterns(code);

  if (isMalicious) {
    return res.json({ result: 'malicious', reason: maliciousReason });
  }

  const vm = new NodeVM({
    console: 'inherit',
    sandbox: {},
    timeout: 1000,
    eval: false,
    wasm: false,
    require: {
      external: false,
      builtin: [],
      root: './',
    },
    wrapper: 'none',
  });

  try {
    vm.run(code);
    res.json({ result: 'success', output: 'Code executed without malicious behavior detected' });
  } catch (error) {
    res.json({ result: 'error', error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
