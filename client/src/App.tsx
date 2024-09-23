import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { useToast } from "@/hooks/use-toast"
import { useEffect, useState } from 'react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { InfoIcon } from 'lucide-react';

enum Status {
  Recovered = 0,
  Valid = 1,
  Tampered = 2,
}

const App = () => {
  const [blockchain, setBlockchain] = useState<{ data: string, status: Status }[]>([]);
  const [newBlockData, setNewBlockData] = useState('');
  const [tamperIndex, setTamperIndex] = useState('');
  const [tamperData, setTamperData] = useState('');

  const { toast } = useToast()

  useEffect(() => {
    fetchInformation();
  }, []);

  const fetchInformation = async () => {
    const response = await fetch('http://localhost:3001/api/information');

    const data = await response.json();

    if (data.success) {
      setBlockchain(data.information);
    } else {
      toast({
        description: `Failed to fetch blockchain information: ${data.error}`,
        variant: 'destructive'
      });
    }
  };

  const create = async () => {
    const response = await fetch('http://localhost:3001/api/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: newBlockData }),
    });

    const result = await response.json();

    if (result.success) {
      fetchInformation();
      setNewBlockData('');
      toast({ description: 'Block created successfully 🎉' });
    } else {
      toast({
        description: `Failed to create block: ${result.error}`,
        variant: 'destructive'
      });
    }
  };

  const tamper = async () => {
    const response = await fetch('http://localhost:3001/api/tamper', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        index: parseInt(tamperIndex),
        newData: tamperData,
      }),
    });

    const result = await response.json();

    if (result.success) {
      fetchInformation();
      setTamperIndex('');
      setTamperData('');
      toast({ description: 'Block tampered with successfully' });
    } else {
      toast({ description: `Failed to tamper block: ${result.error}`, variant: 'destructive' });
    }
  };

  const getStatusColor = (status: Status) => {
    switch (status) {
      case Status.Recovered:
        return 'bg-green-100 border-green-500';
      case Status.Valid:
        return 'bg-blue-100 border-blue-500';
      case Status.Tampered:
        return 'bg-red-100 border-red-500';
      default:
        return 'bg-gray-100 border-gray-500';
    }
  };

  return (
    <div className='container mx-auto max-w-2xl p-4'>
      <div className='space-y-6'>
        <Card>
          <CardHeader>
            <CardTitle>Create a new block</CardTitle>
          </CardHeader>
          <CardContent>
            <div className='flex space-x-2'>
              <Input
                value={newBlockData}
                onChange={(e) => setNewBlockData(e.target.value)}
                placeholder='Enter block data'
              />
              <Button onClick={create}>Create</Button>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Tamper with a block</CardTitle>
          </CardHeader>
          <CardContent>
            <div className='flex space-x-2'>
              <Input
                value={tamperIndex}
                onChange={(e) => setTamperIndex(e.target.value)}
                placeholder='Block index'
                type='number'
              />
              <Input
                value={tamperData}
                onChange={(e) => setTamperData(e.target.value)}
                placeholder='New data'
              />
              <Button variant='destructive' onClick={tamper}>
                Tamper
              </Button>
            </div>
          </CardContent>
        </Card>
        {blockchain.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                Blockchain
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger>
                      <InfoIcon className="h-5 w-5" />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>Blue: Valid</p>
                      <p>Red: Tampered</p>
                      <p>Green: Recovered</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className='space-y-2'>
                {blockchain.map((block, index) => (
                  <li
                    key={index}
                    className={`rounded-md p-2 border ${getStatusColor(block.status)}`}
                  >
                    <strong>Block {index}:</strong> {block.data}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default App;
