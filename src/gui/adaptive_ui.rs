use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::gui::role_based_ui::{UserProfile, ExpertiseLevel, UserRole};

/// Adaptive UI system that learns from user behavior and adjusts interface accordingly
#[derive(Debug, Clone)]
pub struct AdaptiveUIManager {
    user_interactions: UserInteractionTracker,
    ui_adaptations: UIAdaptations,
    learning_engine: LearningEngine,
    contextual_help: ContextualHelpSystem,
}

#[derive(Debug, Clone, Default)]
pub struct UserInteractionTracker {
    pub feature_usage_count: HashMap<String, u32>,
    pub task_completion_times: HashMap<String, Vec<f32>>, // seconds
    pub error_frequencies: HashMap<String, u32>,
    pub help_requests: HashMap<String, u32>,
    pub abandoned_tasks: Vec<String>,
    pub successful_workflows: Vec<WorkflowPattern>,
}

#[derive(Debug, Clone)]
pub struct WorkflowPattern {
    pub name: String,
    pub steps: Vec<String>,
    pub success_rate: f32,
    pub average_duration_seconds: f32,
}

#[derive(Debug, Clone, Default)]
pub struct UIAdaptations {
    pub suggested_shortcuts: HashMap<String, String>,
    pub prioritized_features: Vec<String>,
    pub simplified_workflows: HashMap<String, Vec<String>>,
    pub adaptive_layouts: HashMap<String, LayoutConfig>,
    pub personalized_defaults: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct LayoutConfig {
    pub widget_positions: HashMap<String, (f32, f32)>,
    pub widget_sizes: HashMap<String, (f32, f32)>,
    pub hidden_elements: Vec<String>,
    pub emphasized_elements: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LearningEngine {
    pub adaptation_rules: Vec<AdaptationRule>,
    pub confidence_threshold: f32,
    pub learning_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AdaptationRule {
    pub name: String,
    pub condition: LearningCondition,
    pub adaptation: UIAdaptation,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub enum LearningCondition {
    FeatureUsageAbove(String, u32),
    ErrorRateAbove(String, f32),
    TaskTimeAbove(String, f32),
    HelpRequestsAbove(String, u32),
    UserExpertiseBetween(ExpertiseLevel, ExpertiseLevel),
    Combined(Vec<LearningCondition>),
}

#[derive(Debug, Clone)]
pub enum UIAdaptation {
    PromoteFeature(String),
    SimplifyWorkflow(String),
    AddShortcut(String, String),
    ShowContextualHelp(String),
    HideAdvancedOption(String),
    SuggestAlternative(String, String),
    CustomizeLayout(String, LayoutConfig),
}

#[derive(Debug, Clone)]
pub struct ContextualHelpSystem {
    pub help_content: HashMap<String, HelpContent>,
    pub onboarding_flows: Vec<OnboardingFlow>,
    pub smart_tooltips: HashMap<String, SmartTooltip>,
    pub interactive_tutorials: Vec<InteractiveTutorial>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelpContent {
    pub title: String,
    pub content: String,
    pub difficulty_level: ExpertiseLevel,
    pub related_features: Vec<String>,
    pub examples: Vec<String>,
    pub troubleshooting: Vec<TroubleshootingStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TroubleshootingStep {
    pub problem: String,
    pub solution: String,
    pub prevention: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OnboardingFlow {
    pub name: String,
    pub target_role: UserRole,
    pub steps: Vec<OnboardingStep>,
    pub completion_tracking: HashMap<String, bool>,
}

#[derive(Debug, Clone)]
pub struct OnboardingStep {
    pub id: String,
    pub title: String,
    pub description: String,
    pub action_required: bool,
    pub help_text: String,
    pub completion_criteria: String,
}

#[derive(Debug, Clone)]
pub struct SmartTooltip {
    pub content: String,
    pub trigger_condition: TooltipTrigger,
    pub urgency: TooltipUrgency,
    pub shown_count: u32,
    pub max_show_count: u32,
}

#[derive(Debug, Clone)]
pub enum TooltipTrigger {
    FirstTime,
    AfterError,
    AfterIdleTime(f32), // seconds
    OnFeatureHover,
    OnComplexAction,
}

#[derive(Debug, Clone)]
pub enum TooltipUrgency {
    Low,    // Can be dismissed easily
    Medium, // Stays visible longer
    High,   // Requires acknowledgment
}

#[derive(Debug, Clone)]
pub struct InteractiveTutorial {
    pub id: String,
    pub name: String,
    pub description: String,
    pub target_expertise: ExpertiseLevel,
    pub estimated_duration_minutes: u32,
    pub steps: Vec<TutorialStep>,
    pub progress: HashMap<String, bool>,
}

#[derive(Debug, Clone)]
pub struct TutorialStep {
    pub id: String,
    pub title: String,
    pub instruction: String,
    pub ui_element: String, // Element to highlight
    pub action_type: TutorialAction,
    pub success_criteria: String,
}

#[derive(Debug, Clone)]
pub enum TutorialAction {
    Click(String),
    Type(String),
    Select(String),
    Hover,
    Wait(f32), // seconds
    Observe,
}

impl AdaptiveUIManager {
    pub fn new() -> Self {
        let mut manager = Self {
            user_interactions: UserInteractionTracker::default(),
            ui_adaptations: UIAdaptations::default(),
            learning_engine: LearningEngine::new(),
            contextual_help: ContextualHelpSystem::new(),
        };

        manager.initialize_help_content();
        manager.initialize_onboarding();
        manager
    }

    pub fn track_feature_usage(&mut self, feature: &str) {
        *self.user_interactions.feature_usage_count.entry(feature.to_string()).or_insert(0) += 1;
        self.apply_learning();
    }

    pub fn track_task_completion(&mut self, task: &str, duration_seconds: f32, success: bool) {
        if success {
            self.user_interactions.task_completion_times
                .entry(task.to_string())
                .or_insert_with(Vec::new)
                .push(duration_seconds);
        } else {
            *self.user_interactions.error_frequencies.entry(task.to_string()).or_insert(0) += 1;
        }

        self.apply_learning();
    }

    pub fn track_help_request(&mut self, context: &str) {
        *self.user_interactions.help_requests.entry(context.to_string()).or_insert(0) += 1;
    }

    pub fn track_task_abandonment(&mut self, task: &str) {
        self.user_interactions.abandoned_tasks.push(task.to_string());
    }

    fn apply_learning(&mut self) {
        if !self.learning_engine.learning_enabled {
            return;
        }

        // Collect adaptations to apply before applying them to avoid borrowing conflicts
        let adaptations_to_apply: Vec<UIAdaptation> = self.learning_engine.adaptation_rules
            .iter()
            .filter(|rule| {
                self.evaluate_learning_condition(&rule.condition) &&
                rule.confidence >= self.learning_engine.confidence_threshold
            })
            .map(|rule| rule.adaptation.clone())
            .collect();

        // Now apply the collected adaptations
        for adaptation in adaptations_to_apply {
            self.apply_adaptation(&adaptation);
        }
    }

    fn evaluate_learning_condition(&self, condition: &LearningCondition) -> bool {
        match condition {
            LearningCondition::FeatureUsageAbove(feature, threshold) => {
                self.user_interactions.feature_usage_count
                    .get(feature)
                    .map(|count| *count > *threshold)
                    .unwrap_or(false)
            }
            LearningCondition::ErrorRateAbove(task, threshold) => {
                let error_count = self.user_interactions.error_frequencies
                    .get(task)
                    .copied()
                    .unwrap_or(0) as f32;

                let success_count = self.user_interactions.task_completion_times
                    .get(task)
                    .map(|times| times.len())
                    .unwrap_or(0) as f32;

                let total = error_count + success_count;
                if total > 0.0 {
                    (error_count / total) > *threshold
                } else {
                    false
                }
            }
            LearningCondition::HelpRequestsAbove(context, threshold) => {
                self.user_interactions.help_requests
                    .get(context)
                    .map(|count| *count > *threshold)
                    .unwrap_or(false)
            }
            LearningCondition::Combined(conditions) => {
                conditions.iter().all(|c| self.evaluate_learning_condition(c))
            }
            _ => false,
        }
    }

    fn apply_adaptation(&mut self, adaptation: &UIAdaptation) {
        match adaptation {
            UIAdaptation::PromoteFeature(feature) => {
                if !self.ui_adaptations.prioritized_features.contains(feature) {
                    self.ui_adaptations.prioritized_features.push(feature.clone());
                }
            }
            UIAdaptation::AddShortcut(action, shortcut) => {
                self.ui_adaptations.suggested_shortcuts.insert(action.clone(), shortcut.clone());
            }
            UIAdaptation::ShowContextualHelp(context) => {
                // Mark this context for showing help
                self.contextual_help.smart_tooltips.insert(
                    context.clone(),
                    SmartTooltip {
                        content: format!("Need help with {}? Click here for guidance.", context),
                        trigger_condition: TooltipTrigger::OnFeatureHover,
                        urgency: TooltipUrgency::Medium,
                        shown_count: 0,
                        max_show_count: 3,
                    }
                );
            }
            _ => {} // Other adaptations not implemented yet
        }
    }

    pub fn get_suggested_features(&self, profile: &UserProfile) -> Vec<String> {
        let mut suggestions = Vec::new();

        // Add frequently used features
        for (feature, &count) in &self.user_interactions.feature_usage_count {
            if count >= 3 { // Used at least 3 times
                suggestions.push(feature.clone());
            }
        }

        // Add role-based suggestions
        match profile.role {
            UserRole::Administrator => {
                suggestions.extend_from_slice(&[
                    "user_management".to_string(),
                    "system_configuration".to_string(),
                    "backup_management".to_string(),
                ]);
            }
            UserRole::SecurityOfficer => {
                suggestions.extend_from_slice(&[
                    "security_audit".to_string(),
                    "access_control".to_string(),
                    "compliance_reports".to_string(),
                ]);
            }
            _ => {}
        }

        suggestions.dedup();
        suggestions
    }

    pub fn render_adaptive_suggestions(&mut self, ui: &mut egui::Ui, profile: &UserProfile) {
        let suggestions = self.get_suggested_features(profile);

        if suggestions.is_empty() {
            return;
        }

        ui.group(|ui| {
            ui.heading("🎯 Personalized Suggestions");
            ui.separator();

            ui.label("Based on your usage patterns:");

            for suggestion in suggestions.iter().take(5) {
                ui.horizontal(|ui| {
                    if ui.small_button("→").clicked() {
                        // Navigate to suggested feature
                        self.track_feature_usage("suggestion_clicked");
                    }
                    ui.small(suggestion);
                });
            }

            if suggestions.len() > 5 {
                ui.small(format!("... and {} more", suggestions.len() - 5));
            }
        });
    }

    pub fn render_contextual_help(&mut self, ui: &mut egui::Ui, context: &str) {
        if let Some(help_content) = self.contextual_help.help_content.get(context) {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label("❓");
                    ui.strong(&help_content.title);
                });

                ui.separator();

                // Show appropriate content based on user expertise
                ui.label(&help_content.content);

                // Show examples for beginners
                if !help_content.examples.is_empty() {
                    ui.collapsing("Examples", |ui| {
                        for example in &help_content.examples {
                            ui.small(format!("• {}", example));
                        }
                    });
                }

                // Show troubleshooting for all users
                if !help_content.troubleshooting.is_empty() {
                    ui.collapsing("Troubleshooting", |ui| {
                        for step in &help_content.troubleshooting {
                            ui.group(|ui| {
                                ui.strong(&step.problem);
                                ui.label(&step.solution);
                                if let Some(prevention) = &step.prevention {
                                    ui.small(format!("Prevention: {}", prevention));
                                }
                            });
                        }
                    });
                }
            });
        }
    }

    pub fn render_onboarding_progress(&mut self, ui: &mut egui::Ui, user_role: &UserRole) {
        let mut current_flow = None;

        for flow in &self.contextual_help.onboarding_flows {
            if flow.target_role == *user_role {
                current_flow = Some(flow);
                break;
            }
        }

        if let Some(flow) = current_flow {
            let completed_steps = flow.completion_tracking.values()
                .filter(|&&completed| completed)
                .count();

            let total_steps = flow.steps.len();
            let progress = completed_steps as f32 / total_steps as f32;

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label("🚀");
                    ui.strong(format!("Getting Started: {}", flow.name));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.small(format!("{}/{} completed", completed_steps, total_steps));
                    });
                });

                ui.add(egui::ProgressBar::new(progress)
                    .text(format!("{:.0}% complete", progress * 100.0)));

                // Show next step
                for step in &flow.steps {
                    if !flow.completion_tracking.get(&step.id).unwrap_or(&false) {
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.label("Next:");
                            ui.strong(&step.title);
                        });
                        ui.small(&step.description);

                        if step.action_required && ui.button("Continue").clicked() {
                            // Mark step as completed (in real implementation)
                        }
                        break;
                    }
                }
            });
        }
    }

    pub fn render_smart_tooltip(&mut self, ui: &mut egui::Ui, element: &str) {
        if let Some(tooltip) = self.contextual_help.smart_tooltips.get_mut(element) {
            if tooltip.shown_count < tooltip.max_show_count {
                let should_show = match tooltip.trigger_condition {
                    TooltipTrigger::FirstTime => tooltip.shown_count == 0,
                    TooltipTrigger::OnFeatureHover => true,
                    _ => false,
                };

                if should_show {
                    let color = match tooltip.urgency {
                        TooltipUrgency::Low => egui::Color32::from_gray(200),
                        TooltipUrgency::Medium => egui::Color32::from_rgb(255, 243, 205),
                        TooltipUrgency::High => egui::Color32::from_rgb(248, 215, 218),
                    };

                    egui::Frame::popup(ui.style())
                        .fill(color)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(&tooltip.content);
                                if ui.small_button("✕").clicked() {
                                    tooltip.shown_count = tooltip.max_show_count; // Dismiss
                                }
                            });
                        });

                    tooltip.shown_count += 1;
                }
            }
        }
    }

    fn initialize_help_content(&mut self) {
        // Storage configuration help
        self.contextual_help.help_content.insert(
            "storage_config".to_string(),
            HelpContent {
                title: "Storage Configuration".to_string(),
                content: "Configure how and where your files are stored. Choose from local storage, cloud providers, or network locations.".to_string(),
                difficulty_level: ExpertiseLevel::Beginner,
                related_features: vec!["backup".to_string(), "encryption".to_string()],
                examples: vec![
                    "Local: Store files on your computer's hard drive".to_string(),
                    "Cloud: Use services like AWS S3 or Google Cloud".to_string(),
                    "Network: Connect to SFTP servers or network drives".to_string(),
                ],
                troubleshooting: vec![
                    TroubleshootingStep {
                        problem: "Connection failed".to_string(),
                        solution: "Check your network connection and credentials".to_string(),
                        prevention: Some("Test connections before saving configuration".to_string()),
                    },
                ],
            },
        );

        // Encryption help
        self.contextual_help.help_content.insert(
            "encryption".to_string(),
            HelpContent {
                title: "Data Encryption".to_string(),
                content: "Encryption protects your data by scrambling it so only you can read it. We recommend always enabling encryption for sensitive data.".to_string(),
                difficulty_level: ExpertiseLevel::Beginner,
                related_features: vec!["security".to_string(), "passwords".to_string()],
                examples: vec![
                    "XSalsa20Poly1305: Fast and secure (recommended)".to_string(),
                    "AES256GCM: Industry standard, widely supported".to_string(),
                ],
                troubleshooting: vec![
                    TroubleshootingStep {
                        problem: "Forgot encryption password".to_string(),
                        solution: "Use password recovery if enabled, otherwise data cannot be recovered".to_string(),
                        prevention: Some("Always backup your encryption passwords securely".to_string()),
                    },
                ],
            },
        );
    }

    fn initialize_onboarding(&mut self) {
        // End user onboarding
        self.contextual_help.onboarding_flows.push(OnboardingFlow {
            name: "Quick Start".to_string(),
            target_role: UserRole::EndUser,
            steps: vec![
                OnboardingStep {
                    id: "welcome".to_string(),
                    title: "Welcome to n0n!".to_string(),
                    description: "Let's get you set up with secure file synchronization.".to_string(),
                    action_required: false,
                    help_text: "This wizard will guide you through the basic setup.".to_string(),
                    completion_criteria: "User acknowledges welcome".to_string(),
                },
                OnboardingStep {
                    id: "select_storage".to_string(),
                    title: "Choose Storage Location".to_string(),
                    description: "Select where you'd like to store your files.".to_string(),
                    action_required: true,
                    help_text: "Local storage is easiest to start with.".to_string(),
                    completion_criteria: "Storage type selected".to_string(),
                },
                OnboardingStep {
                    id: "enable_encryption".to_string(),
                    title: "Enable Encryption".to_string(),
                    description: "Protect your files with encryption.".to_string(),
                    action_required: true,
                    help_text: "We strongly recommend enabling encryption for security.".to_string(),
                    completion_criteria: "Encryption configured".to_string(),
                },
            ],
            completion_tracking: HashMap::new(),
        });
    }

    pub fn get_learning_insights(&self) -> Vec<String> {
        let mut insights = Vec::new();

        // Analyze feature usage patterns
        if let Some((most_used, &count)) = self.user_interactions.feature_usage_count
            .iter()
            .max_by_key(|(_, &count)| count) {
            if count > 10 {
                insights.push(format!("You use '{}' frequently. Consider creating a shortcut.", most_used));
            }
        }

        // Analyze error patterns
        if let Some((problematic_task, &error_count)) = self.user_interactions.error_frequencies
            .iter()
            .max_by_key(|(_, &count)| count) {
            if error_count > 3 {
                insights.push(format!("You've had difficulties with '{}'. Would you like help?", problematic_task));
            }
        }

        // Analyze help requests
        if let Some((help_context, &request_count)) = self.user_interactions.help_requests
            .iter()
            .max_by_key(|(_, &count)| count) {
            if request_count > 2 {
                insights.push(format!("Consider reviewing the tutorial for '{}'.", help_context));
            }
        }

        insights
    }
}

impl LearningEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            adaptation_rules: Vec::new(),
            confidence_threshold: 0.7,
            learning_enabled: true,
        };

        engine.initialize_rules();
        engine
    }

    fn initialize_rules(&mut self) {
        // Rule: Promote frequently used features
        self.adaptation_rules.push(AdaptationRule {
            name: "Promote Popular Features".to_string(),
            condition: LearningCondition::FeatureUsageAbove("any".to_string(), 5),
            adaptation: UIAdaptation::PromoteFeature("frequently_used".to_string()),
            confidence: 0.8,
        });

        // Rule: Show help for error-prone tasks
        self.adaptation_rules.push(AdaptationRule {
            name: "Help with Difficult Tasks".to_string(),
            condition: LearningCondition::ErrorRateAbove("any".to_string(), 0.3),
            adaptation: UIAdaptation::ShowContextualHelp("error_prone_task".to_string()),
            confidence: 0.9,
        });
    }
}

impl ContextualHelpSystem {
    pub fn new() -> Self {
        Self {
            help_content: HashMap::new(),
            onboarding_flows: Vec::new(),
            smart_tooltips: HashMap::new(),
            interactive_tutorials: Vec::new(),
        }
    }
}

impl Default for AdaptiveUIManager {
    fn default() -> Self {
        Self::new()
    }
}