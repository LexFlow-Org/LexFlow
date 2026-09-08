import { useEffect, useRef, useState } from 'react';
import { getSessionGeneration, readSessionData, writeSessionData } from '../utils/sessionData';

// Preserve navigation state in memory, while rejecting writes from a locked session.
export function useSessionState(key, fallback) {
  const generation = useRef(getSessionGeneration());
  const [value, setValue] = useState(() => readSessionData(key, fallback));
  useEffect(() => {
    writeSessionData(key, value, generation.current);
  }, [key, value]);
  return [value, setValue];
}
