import { ApiResponse } from '../types/model';

const KNOWLEDGE_API_BASE_URL = '/api/v1/knowledge';

export interface SaveAgentRequest {
  content: string;
}

// One selectable agent-scan detection rule (skill).
export interface AgentSkill {
  name: string;         // directory name, sent back as a --skills value
  title: string;        // human-readable label
  description: string;  // short description of what the rule tests
  recommended: boolean; // part of the default detection set
}

export const agentApi = {
  // Get the Agent list
  async getAgentNames(): Promise<ApiResponse<string[]>> {
    const response = await fetch(`${KNOWLEDGE_API_BASE_URL}/agent/names`);
    return response.json();
  },

  // Get Agent details
  async getAgent(name: string): Promise<ApiResponse<string>> {
    const response = await fetch(`${KNOWLEDGE_API_BASE_URL}/agent/${name}`);
    return response.json();
  },

  // Save an Agent
  async saveAgent(name: string, content: string): Promise<ApiResponse<void>> {
    const response = await fetch(`${KNOWLEDGE_API_BASE_URL}/agent/${name}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ content }),
    });
    return response.json();
  },

  // Test connection
  async testConnection(content: string): Promise<ApiResponse<void>> {
    const response = await fetch(`${KNOWLEDGE_API_BASE_URL}/agent/connect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ content }),
    });
    return response.json();
  },

  // Delete an Agent
  async deleteAgent(name: string): Promise<ApiResponse<void>> {
    const response = await fetch(`${KNOWLEDGE_API_BASE_URL}/agent/${name}`, {
      method: 'DELETE',
    });
    return response.json();
  },

  // Prompt test
  async promptTest(content: string, prompt: string): Promise<ApiResponse<string>> {
    const response = await fetch(`${KNOWLEDGE_API_BASE_URL}/agent/prompt_test`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ content, prompt }),
    });
    return response.json();
  },

  // Get Agent templates
  async getTemplates(language: string = 'en'): Promise<ApiResponse<any>> {
    const response = await fetch(`${KNOWLEDGE_API_BASE_URL}/agent/template?language=${language}`);
    return response.json();
  },

  // List the agent-scan detection rules (skills) available for selection.
  // The endpoint returns { skills: [...] } directly rather than an ApiResponse envelope.
  async getSkills(): Promise<{ skills: AgentSkill[] }> {
    const response = await fetch(`${KNOWLEDGE_API_BASE_URL}/agent/skills`);
    return response.json();
  },
};
