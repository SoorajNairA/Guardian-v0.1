import { cn } from '@/lib/utils';

interface StatusBadgeProps {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'loading';
  className?: string;
}

const StatusBadge = ({ status, className }: StatusBadgeProps) => {
  const baseClasses = "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium";
  
  const statusClasses = {
    healthy: "bg-success/10 text-success border border-success/20",
    degraded: "bg-warning/10 text-warning border border-warning/20", 
    unhealthy: "bg-destructive/10 text-destructive border border-destructive/20",
    loading: "bg-muted/10 text-muted-foreground border border-muted/20 animate-pulse"
  };

  const statusLabels = {
    healthy: "Healthy",
    degraded: "Degraded", 
    unhealthy: "Unhealthy",
    loading: "Checking..."
  };

  return (
    <span className={cn(baseClasses, statusClasses[status], className)}>
      {statusLabels[status]}
    </span>
  );
};

export default StatusBadge;