package util;

import java.util.List;

public class ProbabilityCombiner {

	public static double conjunctionAssumingIndependence(List<Double> values) {
		double mult = 1d;
		for (double value : values)
			mult *= value;
		return mult;
	}
	
	public static double randomlyPickingOne(List<Double> values) {
		if (values.size() > 0) {
			double sum = 0d;
			for (double value : values)
				sum += value;
			return sum / (double)values.size();
		}
		else
			return 0d;
	}
	
	public static double disjunctionAssumingIndependence(List<Double> values) {
		if (values.size() > 0) {
			double sum = 0d;
			int sgn = 1;
			for (int i = 1; i <= values.size(); i++) {
				double partialSum = 0d;
				CombinationIterator<Double> combIterator = new CombinationIterator<>(values, i);
				List<Double> subset = combIterator.nextCombinationOrdered();
				while (subset != null) {
					partialSum += conjunctionAssumingIndependence(subset);
					subset = combIterator.nextCombinationOrdered();
				}
				sum += (double)sgn * partialSum;
				sgn *= -1;
			}
			return sum;
		}
		else
			return 0d;
	}
	
}
