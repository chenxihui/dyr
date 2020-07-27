package util;

public class FSimCoincidenceCount implements FingerprintSimilarity {

	@Override
	public int similarity(String fp1, String fp2) {
		int count = 0;
		if (fp1.length() == fp2.length()) 
			for (int i = 0; i < fp1.length(); i++)
				if (fp1.charAt(i) == fp2.charAt(i))
					count++;
		return count;
	}

}
