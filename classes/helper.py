"""Helper methods for data processing."""
import logging

class Helper:
    """Helper class with methods to help processing data for Misp and ArcSight."""

    def getValueFromObject(self, dictionaries, dot_filter, convertFunction=None, mergeFunction=None, iteration=1):
        """Extract value from nested dictionary according to filter.
        Return value or values from nested dictionaries based on the string representation.
        If there are multiple values (e.g. tag names) merge them.
        
        Args
            dictionaries (list or dict): Dictionaries from which the values will be extracted.
            dot_filter (string): Filter as a string representative of object with dots. Example: Event.Tag.name
            convertFunction (func): Function which converts values before return
            mergeFunction (func): Function which merges multiple values
            iteration (int): Maximum number of recursions.

        Returns:
            Extracted values merged and converted with provided functions.

        Exits:
            If Maximum number of iterations were reached.

        Todo:
            Check if it is efficient enough. If not create an iterational version of this function.

        """

        if convertFunction is None:
            convertFunction = self._convertReturn
        if mergeFunction is None:
            mergeFunction = self._mergeExtract

        max_iterations = 100
        if iteration >= max_iterations:
            logging.error('Maximum number ({}) of iterations were reached in getValueFromObject method.'.format(max_iterations))
            exit()

        if dot_filter != '' and dot_filter[len(dot_filter)-1] != '.':
            # Add dot at the end for easier and more clear processing
            dot_filter += '.'

        if '.' not in dot_filter:
            # If there is no dot it should be a string with a value
            if not dot_filter:
                # Dot was appended at the end of filter. Last element is empty.
                return convertFunction(dictionaries)
            elif dot_filter in dictionaries:
                # Convert string value accordingly
                print(dot_filter, dictionaries) # TODO - remove. It's just for test. This whole elif should not happen ever.
                exit()
                return convertFunction(dictionaries[dot_filter])
            return ''

        key = dot_filter[:dot_filter.find('.')]
        dot_filter = dot_filter[dot_filter.find('.')+1:]

        if not isinstance(dictionaries, list):
            # Create one-element list for easier and more clear processing
            dictionaries = [dictionaries]

        values = []
        # 3. Merge all values from the list
        for dictionary in dictionaries:
            if key in dictionary:
                values.append(self.getValueFromObject(dictionary[key], dot_filter, convertFunction, mergeFunction, iteration+1))

        return mergeFunction(values)

    def _mergeExtract(self, values):
        """Extract value from one elemented lists.

        Args:
            list: List of values to merge

        Example:
            self._mergeExtract([[[1]]]) returns 1

        """
        while isinstance(values, list) and len(values) == 1:
            values = values[0]
        return values

    def _convertReturn(self, value):
        """Return the same value.
        This method is required to keep the code clean.

        Args:
            values (any): Value to return.

        Returns:
            any: Not modified value.
            
        """
        return value

