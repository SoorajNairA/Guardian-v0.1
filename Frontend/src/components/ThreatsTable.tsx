import { ThreatDetection } from '@/lib/api';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from './ui/table';
import { Badge } from './ui/badge';

interface ThreatsTableProps {
  threats: ThreatDetection[];
}

const ThreatsTable = ({ threats }: ThreatsTableProps) => {
  if (threats.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-6 text-center">
        <p className="text-muted-foreground">No threats detected</p>
      </div>
    );
  }

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'destructive';
    if (confidence >= 0.6) return 'secondary';
    return 'default';
  };

  const formatConfidence = (confidence: number) => {
    return `${(confidence * 100).toFixed(1)}%`;
  };

  return (
    <div className="rounded-lg border border-border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Category</TableHead>
            <TableHead>Confidence</TableHead>
            <TableHead>Details</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {threats.map((threat, index) => (
            <TableRow key={index}>
              <TableCell className="font-medium">
                {threat.category}
              </TableCell>
              <TableCell>
                <Badge variant={getConfidenceColor(threat.confidence_score)}>
                  {formatConfidence(threat.confidence_score)}
                </Badge>
              </TableCell>
              <TableCell className="max-w-md">
                <div className="text-sm text-muted-foreground">
                  {threat.details || 'No additional details'}
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
};

export default ThreatsTable;