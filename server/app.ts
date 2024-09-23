import cors from 'cors';
import express from 'express';
import init, { Verifier, Block, Status } from './lib';

await init({ locateFile: (path: string) => `./lib/${path}` });

const app = express();
const port = 3001;

app.use(cors());
app.use(express.json());

const SECRET_KEY = 'some-super-seekrit-key';
const verifier = new Verifier(SECRET_KEY);

// Not exposed to clients.
let blockchain: Block[] = [];

// Exposed via the /information endpoint.
let information: { data: string; status: Status }[] = [];

app.post('/api/create', (req, res) => {
  const { data } = req.body;

  try {
    const newBlock = verifier.create_block(data);
    blockchain.push(newBlock);
    res.json({ success: true, block: newBlock });
  } catch (error) {
    res.status(400).json({ success: false, error: error.toString() });
  }
});

app.get('/api/information', (_, res) => {
  if (blockchain.length === 0)
    return res.status(404).json({ success: false, error: 'No blocks found' });

  try {
    const state = verifier.information(blockchain).reverse();

    information = state.map((blockInfo) => ({
      data: blockInfo.block.data,
      status: blockInfo.status,
    }));

    blockchain = state.map((blockInfo) => blockInfo.block);

    res.json({ success: true, information });
  } catch (error) {
    res.status(400).json({ success: false, error: error.toString() });
  }
});

app.post('/api/tamper', (req, res) => {
  const { index, newData } = req.body;

  if (index < 0 || index >= blockchain.length)
    return res
      .status(400)
      .json({ success: false, error: 'Invalid block index' });

  let tamperedBlock = blockchain[index];

  tamperedBlock.data = newData;

  blockchain[index] = tamperedBlock;

  res.json({ success: true });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
