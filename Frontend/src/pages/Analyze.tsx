import { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertCircle, Shield, Brain, Globe, Loader2, Eye, Code2 } from 'lucide-react';
import { guardianApi, AnalysisRequest, AnalysisResponse, RateLimitHeaders } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import ThreatsTable from '@/components/ThreatsTable';
import RateLimitHeadersComponent from '@/components/RateLimitHeaders';
import CodeBlock from '@/components/CodeBlock';

const Analyze = () => {
  const [text, setText] = useState('');
  const [modelVersion, setModelVersion] = useState('');
  const [complianceMode, setComplianceMode] = useState<'strict' | 'moderate' | 'permissive' | ''>('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [rateLimitHeaders, setRateLimitHeaders] = useState<RateLimitHeaders>({});
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('results');
  
  const { toast } = useToast();
  
  const maxLength = 100000;
  const currentLength = text.length;

  const handleAnalyze = useCallback(async () => {
    if (!text.trim()) {
      toast({
        title: "Validation Error",
        description: "Please enter some text to analyze",
        variant: "destructive",
      });
      return;
    }
    
    if (complianceMode && !['strict', 'moderate', 'permissive'].includes(complianceMode)) {
      toast({
        title: "Validation Error", 
        description: "Compliance mode must be one of: strict, moderate, permissive",
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setResult(null);
    setRateLimitHeaders({});

    try {
      const request: AnalysisRequest = {
        text: text.trim(),
        config: {}
      };
      
      if (modelVersion.trim()) {
        request.config!.model_version = modelVersion.trim();
      }
      
      if (complianceMode) {
        request.config!.compliance_mode = complianceMode;
      }

      const response = await guardianApi.analyze(request);
      setResult(response.data);
      setRateLimitHeaders(response.headers);
      setActiveTab('results');
      
      toast({
        title: "Analysis Complete",
        description: `Risk score: ${response.data.risk_score.toFixed(1)}%`,
      });
    } catch (err: any) {
      console.error('Analysis failed:', err);
      setError(err.message);
      
      if (err.headers) {
        setRateLimitHeaders(err.headers);
      }
      
      if (err.status === 401 || err.status === 403) {
        toast({
          title: "Authentication Error",
          description: "Invalid or missing API key. Check your settings.",
          variant: "destructive",
        });
      } else if (err.status === 429) {
        const retryAfter = err.headers?.retryAfter;
        toast({
          title: "Rate Limited",
          description: retryAfter ? `Rate limited. Retry after ${retryAfter} seconds.` : "Rate limited. Please try again later.",
          variant: "destructive",
        });
      } else {
        toast({
          title: "Analysis Failed",
          description: err.message || "An unexpected error occurred",
          variant: "destructive",
        });
      }
    } finally {
      setIsAnalyzing(false);
    }
  }, [text, modelVersion, complianceMode, toast]);

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'destructive';
    if (score >= 60) return 'secondary';
    if (score >= 40) return 'default';
    return 'default';
  };

  const getRiskScoreLabel = (score: number) => {
    if (score >= 80) return 'High Risk';
    if (score >= 60) return 'Medium Risk';
    if (score >= 40) return 'Low Risk';
    return 'Very Low Risk';
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center space-x-3">
        <div className="h-10 w-10 rounded-lg bg-gradient-primary flex items-center justify-center">
          <Shield className="h-6 w-6 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Analysis Playground</h1>
          <p className="text-muted-foreground">Test Guardian API analysis with real-time results</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Section */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Code2 className="h-5 w-5" />
                <span>Input Text</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="analysis-text">Text to Analyze</Label>
                  <span className={`text-sm ${currentLength > maxLength * 0.9 ? 'text-destructive' : 'text-muted-foreground'}`}>
                    {currentLength.toLocaleString()} / {maxLength.toLocaleString()}
                  </span>
                </div>
                <Textarea
                  id="analysis-text"
                  placeholder="Enter the text you want to analyze for threats..."
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  className="min-h-[200px] font-mono text-sm"
                  maxLength={maxLength}
                />
              </div>

              {/* Configuration */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="model-version">Model Version (Optional)</Label>
                  <Input
                    id="model-version"
                    placeholder="e.g., v2.1"
                    value={modelVersion}
                    onChange={(e) => setModelVersion(e.target.value)}
                    maxLength={50}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="compliance-mode">Compliance Mode</Label>
                  <Select value={complianceMode} onValueChange={(value: any) => setComplianceMode(value)}>
                    <SelectTrigger>
                      <SelectValue placeholder="Default mode" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="strict">Strict</SelectItem>
                      <SelectItem value="moderate">Moderate</SelectItem>
                      <SelectItem value="permissive">Permissive</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Button
                onClick={handleAnalyze}
                disabled={isAnalyzing || !text.trim()}
                className="w-full"
                size="lg"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Brain className="mr-2 h-4 w-4" />
                    Analyze Text
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Rate Limit Headers */}
          <RateLimitHeadersComponent headers={rateLimitHeaders} />
        </div>

        {/* Results Section */}
        <div className="space-y-4">
          {error && (
            <Card className="border-destructive/20 bg-destructive/5">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2 text-destructive">
                  <AlertCircle className="h-5 w-5" />
                  <span className="font-medium">Analysis Failed</span>
                </div>
                <p className="mt-2 text-sm text-destructive/80">{error}</p>
              </CardContent>
            </Card>
          )}

          {result && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span className="flex items-center space-x-2">
                    <Eye className="h-5 w-5" />
                    <span>Analysis Results</span>
                  </span>
                  <Badge variant={getRiskScoreColor(result.risk_score)} className="text-sm">
                    {getRiskScoreLabel(result.risk_score)}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs value={activeTab} onValueChange={setActiveTab}>
                  <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="results">Results</TabsTrigger>
                    <TabsTrigger value="raw">Raw JSON</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="results" className="space-y-4">
                    {/* Risk Score */}
                    <div className="text-center p-4 bg-secondary/20 rounded-lg">
                      <div className="text-3xl font-bold text-primary">
                        {result.risk_score.toFixed(1)}%
                      </div>
                      <div className="text-sm text-muted-foreground">Risk Score</div>
                    </div>

                    {/* Metadata */}
                    {result.metadata && (
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        {result.metadata.is_ai_generated !== undefined && (
                          <div className="text-center p-3 bg-card border rounded-lg">
                            <div className="font-medium">
                              {result.metadata.is_ai_generated ? 'Yes' : 'No'}
                            </div>
                            <div className="text-xs text-muted-foreground">AI Generated</div>
                          </div>
                        )}
                        {result.metadata.language && (
                          <div className="text-center p-3 bg-card border rounded-lg">
                            <div className="font-medium flex items-center justify-center space-x-1">
                              <Globe className="h-4 w-4" />
                              <span>{result.metadata.language}</span>
                            </div>
                            <div className="text-xs text-muted-foreground">Language</div>
                          </div>
                        )}
                        <div className="text-center p-3 bg-card border rounded-lg">
                          <div className="font-mono text-sm">{result.request_id}</div>
                          <div className="text-xs text-muted-foreground">Request ID</div>
                        </div>
                      </div>
                    )}

                    {/* Threats */}
                    <div>
                      <h3 className="text-lg font-semibold mb-3">Detected Threats</h3>
                      <ThreatsTable threats={result.threats_detected} />
                    </div>
                  </TabsContent>

                  <TabsContent value="raw">
                    <CodeBlock code={JSON.stringify(result, null, 2)} language="json" />
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          )}

          {!result && !error && !isAnalyzing && (
            <Card className="border-dashed border-2">
              <CardContent className="p-8 text-center">
                <Brain className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-medium mb-2">Ready to Analyze</h3>
                <p className="text-muted-foreground">Enter some text and click "Analyze Text" to see results here</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default Analyze;