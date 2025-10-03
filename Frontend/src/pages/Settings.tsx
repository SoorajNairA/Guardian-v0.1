import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Settings as SettingsIcon, Save, RotateCcw, Key, Globe, Eye, EyeOff } from 'lucide-react';
import { getApiConfig, updateApiConfig } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

const Settings = () => {
  const [apiUrl, setApiUrl] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  
  const { toast } = useToast();

  const envDefaults = {
    apiUrl: import.meta.env.VITE_API_URL || 'http://localhost:8000',
    apiKey: import.meta.env.VITE_GUARDIAN_API_KEY || '',
  };

  useEffect(() => {
    const config = getApiConfig();
    setApiUrl(config.baseUrl);
    setApiKey(config.apiKey);
  }, []);

  useEffect(() => {
    const config = getApiConfig();
    const hasUrlChange = apiUrl !== config.baseUrl;
    const hasKeyChange = apiKey !== config.apiKey;
    setHasChanges(hasUrlChange || hasKeyChange);
  }, [apiUrl, apiKey]);

  const handleSave = () => {
    if (!apiUrl.trim()) {
      toast({
        title: "Validation Error",
        description: "API URL is required",
        variant: "destructive",
      });
      return;
    }

    // Basic URL validation
    try {
      new URL(apiUrl);
    } catch {
      toast({
        title: "Validation Error",
        description: "Please enter a valid API URL",
        variant: "destructive",
      });
      return;
    }

    updateApiConfig(apiUrl.trim(), apiKey.trim());
    setHasChanges(false);
    
    toast({
      title: "Settings Saved",
      description: "API configuration has been updated successfully",
    });
  };

  const handleReset = () => {
    setApiUrl(envDefaults.apiUrl);
    setApiKey(envDefaults.apiKey);
    
    updateApiConfig(envDefaults.apiUrl, envDefaults.apiKey);
    setHasChanges(false);
    
    toast({
      title: "Settings Reset",
      description: "Configuration has been reset to environment defaults",
    });
  };

  const maskApiKey = (key: string) => {
    if (!key) return '';
    if (key.length <= 8) return '*'.repeat(key.length);
    return key.slice(0, 4) + '*'.repeat(key.length - 8) + key.slice(-4);
  };

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      {/* Header */}
      <div className="flex items-center space-x-3">
        <div className="h-10 w-10 rounded-lg bg-gradient-card flex items-center justify-center">
          <SettingsIcon className="h-6 w-6 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Settings</h1>
          <p className="text-muted-foreground">Configure Guardian API connection and preferences</p>
        </div>
      </div>

      {/* API Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Key className="h-5 w-5" />
            <span>API Configuration</span>
            {hasChanges && (
              <Badge variant="secondary" className="ml-auto">
                Unsaved Changes
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* API URL */}
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <Globe className="h-4 w-4 text-muted-foreground" />
              <Label htmlFor="api-url">API Base URL</Label>
            </div>
            <Input
              id="api-url"
              type="url"
              placeholder="https://api.example.com"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              className="font-mono"
            />
            <p className="text-sm text-muted-foreground">
              The base URL for your Guardian API instance
            </p>
          </div>

          {/* API Key */}
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <Key className="h-4 w-4 text-muted-foreground" />
              <Label htmlFor="api-key">API Key</Label>
            </div>
            <div className="relative">
              <Input
                id="api-key"
                type={showApiKey ? 'text' : 'password'}
                placeholder="Enter your Guardian API key"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className="font-mono pr-10"
              />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="absolute right-1 top-1 h-7 w-7 text-muted-foreground hover:text-foreground"
                onClick={() => setShowApiKey(!showApiKey)}
              >
                {showApiKey ? (
                  <EyeOff className="h-4 w-4" />
                ) : (
                  <Eye className="h-4 w-4" />
                )}
              </Button>
            </div>
            <p className="text-sm text-muted-foreground">
              Your API key for authenticating with the Guardian service
            </p>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-between pt-4 border-t border-border">
            <Button
              variant="outline"
              onClick={handleReset}
              className="flex items-center space-x-2"
            >
              <RotateCcw className="h-4 w-4" />
              <span>Reset to Defaults</span>
            </Button>
            
            <Button
              onClick={handleSave}
              disabled={!hasChanges}
              className="flex items-center space-x-2"
            >
              <Save className="h-4 w-4" />
              <span>Save Changes</span>
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Environment Info */}
      <Card className="border-info/20 bg-info/5">
        <CardHeader>
          <CardTitle className="text-sm flex items-center space-x-2">
            <Badge variant="outline" className="text-info border-info/50">
              Environment
            </Badge>
            <span>Default Configuration</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 gap-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">VITE_API_URL</span>
              <code className="bg-muted/50 px-2 py-1 rounded font-mono text-xs">
                {envDefaults.apiUrl}
              </code>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">VITE_GUARDIAN_API_KEY</span>
              <code className="bg-muted/50 px-2 py-1 rounded font-mono text-xs">
                {envDefaults.apiKey ? maskApiKey(envDefaults.apiKey) : 'Not set'}
              </code>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            These are the default values from your environment variables. 
            Settings saved here will override these defaults locally.
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

export default Settings;