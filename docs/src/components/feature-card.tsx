import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LucideIcon } from "lucide-react";

interface FeatureCardProps {
  title: string;
  description: string;
  icon: LucideIcon;
  badge?: string;
  badgeVariant?: "default" | "destructive" | "outline" | "secondary";
  features: string[];
}

export function FeatureCard({
  title,
  description,
  icon: Icon,
  badge,
  badgeVariant = "default",
  features,
}: FeatureCardProps) {
  return (
    <Card className="bg-card/50 border-border/50 hover:border-violet/30 transition-all duration-300 hover:shadow-lg hover:shadow-violet/5 group">
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="w-12 h-12 rounded-lg bg-violet/10 flex items-center justify-center mb-4 group-hover:bg-violet/20 transition-colors">
            <Icon className="w-6 h-6 text-violet" />
          </div>
          {badge && (
            <Badge variant={badgeVariant} className="text-xs">
              {badge}
            </Badge>
          )}
        </div>
        <CardTitle className="text-xl">{title}</CardTitle>
        <CardDescription className="text-muted-foreground">
          {description}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2">
          {features.map((feature, index) => (
            <li key={index} className="flex items-start gap-2 text-sm text-muted-foreground">
              <span className="text-violet mt-1">•</span>
              {feature}
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
