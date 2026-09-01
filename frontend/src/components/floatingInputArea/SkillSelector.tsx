import React, { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '../ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { ShieldCheck, Check } from 'lucide-react';
import { agentApi, AgentSkill } from '../../lib/agentApi';

interface SkillSelectorProps {
  selectedSkills: string[];
  onSkillsSelect: (skills: string[]) => void;
  taskType?: string;
}

/**
 * Detection-rule (skill) picker for Agent-Scan.
 *
 * Lets the user run a targeted subset of rules or, via the quick actions,
 * the recommended default set or the full catalogue. An empty selection is
 * intentional and means "let the backend run the default detection set" — the
 * button and an inline hint make that explicit so the empty state is never
 * mistaken for "nothing will be scanned".
 */
const SkillSelector: React.FC<SkillSelectorProps> = ({
  selectedSkills,
  onSkillsSelect,
  taskType,
}) => {
  const { t } = useTranslation();
  const [showMenu, setShowMenu] = useState(false);
  const [menuPosition, setMenuPosition] = useState<'top' | 'bottom'>('top');
  const [loading, setLoading] = useState(false);
  const [skills, setSkills] = useState<AgentSkill[]>([]);
  const menuRef = useRef<HTMLDivElement>(null);

  const shouldShow = taskType === 'Agent-Scan';

  // Load the rule catalogue the first time the picker is relevant.
  useEffect(() => {
    if (shouldShow && skills.length === 0 && !loading) {
      const load = async () => {
        setLoading(true);
        try {
          const data = await agentApi.getSkills();
          setSkills(data?.skills || []);
        } catch (error) {
          console.error('Failed to load detection rules:', error);
        } finally {
          setLoading(false);
        }
      };
      load();
    }
  }, [shouldShow, skills.length, loading]);

  const toggleSkill = (name: string) => {
    if (selectedSkills.includes(name)) {
      onSkillsSelect(selectedSkills.filter(n => n !== name));
    } else {
      onSkillsSelect([...selectedSkills, name]);
    }
  };

  const selectRecommended = () =>
    onSkillsSelect(skills.filter(s => s.recommended).map(s => s.name));
  const selectAll = () => onSkillsSelect(skills.map(s => s.name));
  const clearAll = () => onSkillsSelect([]);

  // Close on outside click.
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (showMenu && menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setShowMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showMenu]);

  const toggleMenu = () => {
    if (!showMenu) {
      const buttonElement = menuRef.current?.querySelector('button');
      if (buttonElement) {
        const rect = buttonElement.getBoundingClientRect();
        const menuHeight = 340;
        const spaceAbove = rect.top;
        const spaceBelow = window.innerHeight - rect.bottom;
        setMenuPosition(spaceAbove >= menuHeight && spaceAbove > spaceBelow ? 'top' : 'bottom');
      }
    }
    setShowMenu(!showMenu);
  };

  if (!shouldShow) {
    return null;
  }

  const label = loading
    ? t('floatingInputArea.buttons.loading')
    : selectedSkills.length === 0
      ? t('floatingInputArea.skillSelection.defaultRules')
      : `${t('floatingInputArea.skillSelection.rules')} ${selectedSkills.length}`;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="relative group skill-menu-container" ref={menuRef}>
          <Button
            size="sm"
            variant="ghost"
            className="p-1 h-8 w-auto border rounded-[10px] gap-1"
            onClick={toggleMenu}
            disabled={loading}
          >
            <ShieldCheck className="w-4 h-4" />
            <span className="text-xs text-gray-600">{label}</span>
          </Button>

          <div
            className={`absolute left-0 bg-white border border-gray-200 rounded-lg shadow-lg transition-all duration-200 ${
              showMenu ? 'opacity-100 visible' : 'opacity-0 invisible'
            } ${menuPosition === 'top' ? 'bottom-full mb-2' : 'top-full mt-2'}`}
            style={{ zIndex: 30, maxHeight: '340px', minWidth: '320px', maxWidth: '460px' }}
          >
            {/* Quick actions */}
            <div className="flex items-center gap-2 p-2 border-b border-gray-200">
              <button
                type="button"
                className="text-xs px-2 py-1 rounded border hover:bg-gray-50 text-gray-600"
                onClick={selectRecommended}
              >
                {t('floatingInputArea.skillSelection.recommended')}
              </button>
              <button
                type="button"
                className="text-xs px-2 py-1 rounded border hover:bg-gray-50 text-gray-600"
                onClick={selectAll}
              >
                {t('floatingInputArea.skillSelection.selectAll')}
              </button>
              <button
                type="button"
                className="text-xs px-2 py-1 rounded border hover:bg-gray-50 text-gray-600"
                onClick={clearAll}
              >
                {t('floatingInputArea.skillSelection.clear')}
              </button>
              <span className="ml-auto text-xs text-gray-400">
                {selectedSkills.length}/{skills.length}
              </span>
            </div>

            {/* Empty-selection hint */}
            {selectedSkills.length === 0 && (
              <div className="px-3 py-2 text-xs text-gray-400 border-b border-gray-100">
                {t('floatingInputArea.skillSelection.emptyHint')}
              </div>
            )}

            {/* Rule list */}
            <div className="p-2 overflow-y-auto" style={{ maxHeight: '250px' }}>
              {skills.map(skill => {
                const selected = selectedSkills.includes(skill.name);
                return (
                  <div
                    key={skill.name}
                    className={`flex items-start gap-2 p-2 hover:bg-gray-100 rounded cursor-pointer ${
                      selected ? 'bg-blue-50' : ''
                    }`}
                    onClick={() => toggleSkill(skill.name)}
                  >
                    <div
                      className={`mt-0.5 w-4 h-4 flex-shrink-0 border rounded flex items-center justify-center ${
                        selected ? 'bg-blue-600 border-blue-600' : 'border-gray-300'
                      }`}
                    >
                      {selected && <Check className="w-3 h-3 text-white" />}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-1">
                        <span className="text-sm font-medium text-gray-700 truncate">
                          {skill.title}
                        </span>
                        {skill.recommended && (
                          <span className="text-[10px] px-1 rounded bg-green-100 text-green-700 flex-shrink-0">
                            {t('floatingInputArea.skillSelection.recommendedBadge')}
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-gray-400 truncate" title={skill.description}>
                        {skill.description}
                      </div>
                    </div>
                  </div>
                );
              })}
              {skills.length === 0 && !loading && (
                <div className="text-xs text-gray-400 p-2">
                  {t('floatingInputArea.skillSelection.empty')}
                </div>
              )}
            </div>
          </div>
        </div>
      </TooltipTrigger>
      <TooltipContent>
        <p>{t('floatingInputArea.skillSelection.tooltip')}</p>
      </TooltipContent>
    </Tooltip>
  );
};

export default SkillSelector;
