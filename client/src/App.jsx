import React, { useState } from 'react';
import CodeAnalyzer from './CodeAnalyzer';

const App = () => {
  const [code, setCode] = useState('');
  const [analyzed, setAnalyzed] = useState(false);
  const [clicked, setClicked] = useState(false);

  const handleCodeChange = (e) => {
    setCode(e.target.value);
  };

  const analyzeCode = () => {
    setClicked(true);
    setAnalyzed(true);
  };

  return (
    <div className="w-screen h-screen flex m-auto bg-white text-black">
      <div className="m-auto flex-col text-center mt-[5rem]">
        <h1>Malicious JavaScript Detector</h1>
        <textarea
          rows="10"
          cols="80"
          value={code}
          onChange={handleCodeChange}
          placeholder="Enter JavaScript code here..."
          className='mt-[3rem] p-[2rem] rounded-lg text-white bg-zinc-800'
        ></textarea>
        <br />
        <button onClick={analyzeCode} className='mt-[1rem] mb-[1rem] text-white'>Start Analyzing</button>
        {analyzed && clicked && <CodeAnalyzer code={code} />}
      </div>
    </div>
  );
};

export default App;
