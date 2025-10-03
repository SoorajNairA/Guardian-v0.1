import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Activity, RefreshCw, Clock, AlertCircle, CheckCircle2, AlertTriangle } from 'lucide-react';
import { guardianApi, HealthResponse, HealthDependency } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import StatusBadge from '@/components/StatusBadge';

const Health = () => {
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  
  const { toast } = useToast();

  const fetchHealth = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await guardianApi.health();
      setHealthData(response.data);
      setLastUpdated(new Date());
      
      if (response.data.status !== 'healthy') {
        toast({
          title: "Health Check Complete",
          description: `System status: ${response.data.status}`,
          variant: response.data.status === 'unhealthy' ? 'destructive' : 'default',
        });
      }
    } catch (err: any) {
      console.error('Health check failed:', err);
      setError(err.message);
      
      if (err.status === 401 || err.status === 403) {
        toast({
          title: "Authentication Error",
          description: "Invalid or missing API key. Check your settings.",
          variant: "destructive",
        });
      } else {
        toast({
          title: "Health Check Failed",
          description: err.message || "Failed to fetch health status",
          variant: "destructive",
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const getStatusIcon = (status: 'healthy' | 'degraded' | 'unhealthy') => {
    switch (status) {
      case 'healthy':
        return <CheckCircle2 className="h-5 w-5 text-success" />;
      case 'degraded':
        return <AlertTriangle className="h-5 w-5 text-warning" />;
      case 'unhealthy':
        return <AlertCircle className="h-5 w-5 text-destructive" />;
    }
  };

  const formatLatency = (latency?: number) => {
    if (!latency && latency !== 0) return 'N/A';
    return `${latency}ms`;
  };

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleString();
    } catch {
      return timestamp;
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-lg bg-gradient-status flex items-center justify-center">
            <Activity className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">System Health</h1>
            <p className="text-muted-foreground">Monitor Guardian API and dependency status</p>
          </div>
        </div>
        
        <Button onClick={fetchHealth} disabled={isLoading} variant="outline">
          <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Error State */}
      {error && (
        <Card className="border-destructive/20 bg-destructive/5">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2 text-destructive">
              <AlertCircle className="h-5 w-5" />
              <span className="font-medium">Health Check Failed</span>
            </div>
            <p className="mt-2 text-sm text-destructive/80">{error}</p>
            <Button onClick={fetchHealth} className="mt-3" variant="outline" size="sm">
              Try Again
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Loading State */}
      {isLoading && !healthData && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-3">
                <div className="h-4 bg-muted/50 rounded animate-pulse" />
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="h-8 bg-muted/50 rounded animate-pulse" />
                  <div className="h-4 bg-muted/50 rounded animate-pulse" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Health Data */}
      {healthData && (
        <>
          {/* Overall Status */}
          <Card className="border-primary/20">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  {getStatusIcon(healthData.status)}
                  <span>Overall System Status</span>
                </div>
                <StatusBadge status={healthData.status} />
              </CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center p-3 bg-secondary/20 rounded-lg">
                <div className="text-2xl font-bold text-primary">
                  {healthData.status.toUpperCase()}
                </div>
                <div className="text-sm text-muted-foreground">Current Status</div>
              </div>
              
              <div className="text-center p-3 bg-secondary/20 rounded-lg">
                <div className="text-lg font-mono">
                  {formatTimestamp(healthData.timestamp)}
                </div>
                <div className="text-sm text-muted-foreground">Last Check</div>
              </div>
              
              {healthData.version && (
                <div className="text-center p-3 bg-secondary/20 rounded-lg">
                  <div className="text-lg font-mono">
                    {healthData.version}
                  </div>
                  <div className="text-sm text-muted-foreground">Version</div>
                </div>
              )}
              
              {lastUpdated && (
                <div className="text-center p-3 bg-secondary/20 rounded-lg">
                  <div className="flex items-center justify-center space-x-1 text-lg">
                    <Clock className="h-4 w-4" />
                    <span>{lastUpdated.toLocaleTimeString()}</span>
                  </div>
                  <div className="text-sm text-muted-foreground">Panel Updated</div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Dependencies */}
          <div>
            <h2 className="text-xl font-semibold mb-4">Dependencies</h2>
            
            {healthData.dependencies.length === 0 ? (
              <Card>
                <CardContent className="p-8 text-center">
                  <Activity className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <h3 className="text-lg font-medium mb-2">No Dependencies</h3>
                  <p className="text-muted-foreground">No dependency information available</p>
                </CardContent>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {healthData.dependencies.map((dep, index) => (
                  <Card key={index} className={`
                    ${dep.status === 'healthy' ? 'border-success/20 bg-success/5' : 
                      dep.status === 'degraded' ? 'border-warning/20 bg-warning/5' : 
                      'border-destructive/20 bg-destructive/5'}
                  `}>
                    <CardHeader className="pb-3">
                      <CardTitle className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          {getStatusIcon(dep.status)}
                          <span className="text-base">{dep.name}</span>
                        </div>
                        <StatusBadge status={dep.status} />
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">Latency</span>
                        <Badge variant="outline" className="font-mono">
                          {formatLatency(dep.latency)}
                        </Badge>
                      </div>
                      
                      {dep.last_check && (
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">Last Check</span>
                          <span className="font-mono text-xs">
                            {new Date(dep.last_check).toLocaleTimeString()}
                          </span>
                        </div>
                      )}
                      
                      {dep.error && (
                        <div className="mt-2 p-2 bg-destructive/10 border border-destructive/20 rounded text-sm">
                          <div className="font-medium text-destructive mb-1">Error Details</div>
                          <div className="text-destructive/80">{dep.error}</div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default Health;