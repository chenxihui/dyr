package util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CombinationIterator<T> {
	
	protected int m;
	protected List<T> objects;
	protected List<Integer> currentIndices;
	
	public CombinationIterator(List<T> objs, int m) {
		if (m <= objs.size()) {
			objects = new ArrayList<>(objs);
			this.m = m;
			currentIndices = null;
		}
		else
			throw new RuntimeException("Size of combinations larger than pool size");
	}
	
	public CombinationIterator(Set<T> objs, int m) {
		if (m <= objs.size()) {
			objects = new ArrayList<>(objs);
			this.m = m;
			currentIndices = null;
		}
		else
			throw new RuntimeException("Size of combinations larger than pool size");
	}
	
	public List<T> nextCombinationOrdered() {
		if (currentIndices == null) {
			currentIndices = new ArrayList<Integer>();
			for (int i = 0; i < m; i++)
				currentIndices.add(i);
		}
		else {
			boolean nextFound = false;
			for (int i = m - 1; !nextFound && i >= 0; i--)
				if (currentIndices.get(i) < objects.size() + i - m) {
					currentIndices.set(i, currentIndices.get(i) + 1);
					for (int j = i + 1; j < m; j++)
						currentIndices.set(j, currentIndices.get(i) + j - i);
					nextFound = true;
				}
			if (!nextFound)
				return null;
		}
		List<T> currentComb = new ArrayList<>();
		for (int i = 0; i < m; i++)
			currentComb.add(objects.get(currentIndices.get(i)));
		return currentComb;
	}
	
	public Set<T> nextCombination() {
		return new HashSet<>(nextCombinationOrdered());
	}

}
