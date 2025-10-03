import { RateLimitHeaders as RateLimitHeadersType } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Clock, Shield, AlertTriangle } from 'lucide-react';

interface RateLimitHeadersProps {
  headers: RateLimitHeadersType;
}

const RateLimitHeaders = ({ headers }: RateLimitHeadersProps) => {
  const hasHeaders = Object.values(headers).some(value => value !== undefined);
  
  if (!hasHeaders) {
    return null;
  }

  const formatResetTime = (resetTimestamp: string) => {
    try {
      const resetTime = new Date(parseInt(resetTimestamp) * 1000);
      return resetTime.toLocaleTimeString();
    } catch {
      return resetTimestamp;
    }
  };

  return (
    <Card className="border-info/20 bg-info/5">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center space-x-2 text-sm">
          <Shield className="h-4 w-4 text-info" />
          <span>Rate Limit Information</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-4 text-sm">
          {headers.limit && (
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Limit</span>
              <Badge variant="secondary">{headers.limit}</Badge>
            </div>
          )}
          
          {headers.remaining && (
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Remaining</span>
              <Badge variant="default">{headers.remaining}</Badge>
            </div>
          )}
          
          {headers.reset && (
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Resets At</span>
              <div className="flex items-center space-x-1">
                <Clock className="h-3 w-3 text-muted-foreground" />
                <span className="font-mono text-xs">{formatResetTime(headers.reset)}</span>
              </div>
            </div>
          )}
          
          {headers.retryAfter && (
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Retry After</span>
              <div className="flex items-center space-x-1">
                <AlertTriangle className="h-3 w-3 text-warning" />
                <Badge variant="secondary">{headers.retryAfter}s</Badge>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default RateLimitHeaders;